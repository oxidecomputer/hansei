// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use testrun::fixture::Matrix;

use std::path::Path;

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    assert_eq!(
        args.len(),
        6,
        "expected fixture-dir set program target-recipe bundle-recipe output"
    );
    let dir = Path::new(&args[0]);
    let matrix = Matrix::read(dir);
    let recipe = matrix.capture_recipe(&args[1]);
    for (path, expected) in [
        (&args[3], recipe.target_recipe().text()),
        (&args[4], recipe.text()),
    ] {
        assert_eq!(
            std::fs::read_to_string(path).expect("read actual build recipe"),
            expected,
            "actual build settings differ from the capture recipe: {path}"
        );
    }
    std::fs::write(
        &args[5],
        recipe.capture_record(dir, &matrix, &args[1], &args[2]),
    )
    .expect("write capture record");
}
