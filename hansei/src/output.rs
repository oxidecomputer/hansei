//! The one aligner behind every columned listing.
//!
//! Each listing used to pad its own columns, and each did it a little
//! differently — one of them measured cells in bytes, so a row holding
//! a box-drawing character pushed every row beside it out of line. The
//! rules live here once instead: widths are measured in characters,
//! the last column is never padded — a type name ends its line, so a
//! terminal soft-wrap belongs to the name and triple-click still
//! copies the whole logical line — and a header row, where a listing
//! has one, is padded with the same widths as the rows it names.

use std::io;

/// Which edge of its column a cell sits against. Counts sit right, so
/// their magnitudes line up; everything else sits left.
pub(crate) enum Align {
    Left,
    Right,
}

/// A columned listing on its way to being printed: rows are collected,
/// then rendered with every column padded to its widest cell.
pub(crate) struct Table {
    columns: usize,
    sep: &'static str,
    aligns: Vec<Align>,
    header: Option<Vec<String>>,
    rows: Vec<Vec<String>>,
}

impl Table {
    /// A table of `columns` columns, every cell left-aligned, columns
    /// two spaces apart.
    pub(crate) fn new(columns: usize) -> Self {
        Self {
            columns,
            sep: "  ",
            aligns: (0..columns).map(|_| Align::Left).collect(),
            header: None,
            rows: Vec::new(),
        }
    }

    /// Set what separates one column from the next.
    pub(crate) fn sep(mut self, sep: &'static str) -> Self {
        self.sep = sep;
        self
    }

    /// Right-align one column.
    pub(crate) fn align_right(mut self, column: usize) -> Self {
        self.aligns[column] = Align::Right;
        self
    }

    /// Name the columns. The header is a row like any other for width
    /// purposes — its labels are padded with the cells they name.
    pub(crate) fn header<I, S>(mut self, cells: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let cells = self.cells(cells);
        self.header = Some(cells);
        self
    }

    /// Add one row.
    pub(crate) fn row<I, S>(&mut self, cells: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let cells = self.cells(cells);
        self.rows.push(cells);
    }

    /// Whether the table holds no rows — a header alone counts for
    /// nothing: a heading over no rows reads as data missing rather
    /// than absent.
    pub(crate) fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// The width one column was padded to: the character count of its
    /// widest cell, header included.
    pub(crate) fn width(&self, column: usize) -> usize {
        self.header
            .iter()
            .chain(&self.rows)
            .map(|row| row[column].chars().count())
            .max()
            .unwrap_or(0)
    }

    /// Render every line, the header's first when there is one. Each
    /// cell but the last is padded to its column's width; the last is
    /// appended as it is.
    pub(crate) fn render(&self) -> Vec<String> {
        let widths: Vec<usize> = (0..self.columns).map(|c| self.width(c)).collect();
        self.header
            .iter()
            .chain(&self.rows)
            .map(|row| {
                let mut line = String::new();
                for (i, cell) in row.iter().enumerate() {
                    if i + 1 == self.columns {
                        line.push_str(cell);
                        break;
                    }
                    let pad = widths[i] - cell.chars().count();
                    match self.aligns[i] {
                        Align::Left => {
                            line.push_str(cell);
                            line.extend(std::iter::repeat_n(' ', pad));
                        }
                        Align::Right => {
                            line.extend(std::iter::repeat_n(' ', pad));
                            line.push_str(cell);
                        }
                    }
                    line.push_str(self.sep);
                }
                line
            })
            .collect()
    }

    /// Write every line, each terminated by a newline.
    pub(crate) fn write(&self, out: &mut dyn io::Write) -> io::Result<()> {
        for line in self.render() {
            writeln!(out, "{line}")?;
        }
        Ok(())
    }

    fn cells<I, S>(&self, cells: I) -> Vec<String>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let cells: Vec<String> = cells.into_iter().map(Into::into).collect();
        debug_assert_eq!(cells.len(), self.columns);
        cells
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rendered(table: &Table) -> Vec<String> {
        table.render()
    }

    /// Every column but the last pads to its widest cell; the last is
    /// left alone, so nothing prints after a line's final cell.
    #[test]
    fn test_columns_pad_to_their_widest_cell_and_the_last_never_pads() {
        let mut t = Table::new(3);
        t.row(["a", "bb", "c"]);
        t.row(["dd", "e", "a much longer cell"]);
        assert_eq!(rendered(&t), ["a   bb  c", "dd  e   a much longer cell"]);
    }

    /// Widths are counted in characters, not bytes: a cell holding
    /// box-drawing characters is three bytes per glyph, and padding to
    /// bytes would push the rows beside it out of line.
    #[test]
    fn test_widths_are_counted_in_characters() {
        let mut t = Table::new(2);
        t.row(["├─ x", "a"]);
        t.row(["long", "b"]);
        assert_eq!(rendered(&t), ["├─ x  a", "long  b"]);
    }

    /// A right-aligned column pads on the left, so magnitudes line up.
    #[test]
    fn test_a_right_aligned_column_pads_on_the_left() {
        let mut t = Table::new(2).align_right(0);
        t.row(["7", "watchers"]);
        t.row(["112", "timers"]);
        assert_eq!(rendered(&t), ["  7  watchers", "112  timers"]);
    }

    /// The header renders first and its labels count toward the widths
    /// like any cell, so the labels sit over their columns.
    #[test]
    fn test_the_header_is_padded_with_the_rows_it_names() {
        let mut t = Table::new(2).header(["KIND", "WHERE"]);
        t.row(["a", "x"]);
        assert_eq!(rendered(&t), ["KIND  WHERE", "a     x"]);
        assert_eq!(t.width(0), 4);
    }

    /// A table with a header but no rows is still empty: the caller
    /// skips it rather than print a heading over nothing.
    #[test]
    fn test_a_header_alone_is_still_empty() {
        let t = Table::new(2).header(["A", "B"]);
        assert!(t.is_empty());
    }

    /// The separator is configurable for the listings whose columns sit
    /// one space apart.
    #[test]
    fn test_the_separator_is_configurable() {
        let mut t = Table::new(2).sep(" ");
        t.row(["a", "b"]);
        t.row(["ccc", "d"]);
        assert_eq!(rendered(&t), ["a   b", "ccc d"]);
    }
}
