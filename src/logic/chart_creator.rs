use std::error::Error;
use std::env;
use std::path::PathBuf;

use plotters::prelude::*;

const CHART_DIR: &str = "cvss_charts";

fn gen_chart_img_name(id: u64) -> String {
    format!("cvss-{}.png", id)
}

fn get_chart_img_path(id: u64) -> PathBuf {
    let mut exe_path = env::current_exe().unwrap();
    let _ = exe_path.pop();
    let exe_path = exe_path.join(CHART_DIR);
    let exe_path = exe_path.join(&gen_chart_img_name(id));
    exe_path
}

pub fn create_cvss_chart(id: u64, base_serverity_count: Vec<(&str, u64)>) -> Result<String, Box<dyn Error + Send>> {
    let img_path = get_chart_img_path(id);
    let root = BitMapBackend::new(&img_path, (640, 480)).into_drawing_area();

    root.fill(&WHITE).unwrap();

    let max_count = *base_serverity_count.iter().map(|(_, x)| {x}).max().unwrap();
    let mut chart = ChartBuilder::on(&root)
        .x_label_area_size(35)
        .y_label_area_size(40)
        .margin(5)
        .caption("CVSS score graph", ("sans-serif", 50.0))
        .build_cartesian_2d(0u32..4u32, 0u64..max_count).unwrap();

    chart
        .configure_mesh()
        .disable_x_mesh()
        .bold_line_style(WHITE.mix(0.3))
        .y_desc("Count")
        .x_desc("Severity")
        .axis_desc_style(("sans-serif", 15))
        .draw().unwrap();


    let bars = base_serverity_count.iter().enumerate().map(|(i, entry)| {
        let x0 = i as u32;

        let mut bar = Rectangle::new([(x0, 0u64), (x0 + 1u32, entry.1)], RGBColor(255, 0, 0).filled());
        bar.set_margin(0, 0, 5, 5);
        bar
    });

    chart.draw_series(bars).unwrap();

    root.present().expect(&format!("Unable to write result to file, please make sure directory {} exists", CHART_DIR));
    Ok(img_path.to_str().unwrap().to_owned())
}