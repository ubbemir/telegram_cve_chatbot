use std::error::Error;
use std::env;
use std::path::PathBuf;

use genpdf::Element as _;
use genpdf::{elements, fonts, style};

use super::nist_api_structs::CPEResponse;

const PDF_DIR: &str = "pdf";
const FONT_DIR: &str = "fonts";

const DEFAULT_FONT_NAME: &'static str = "OpenSans";

fn gen_pdf_file_name(id: u64) -> String {
    format!("{}.pdf", id)
}

fn get_pdf_file_path(id: u64) -> PathBuf {
    let mut exe_path = env::current_exe().unwrap();
    let _ = exe_path.pop();
    exe_path.push(PDF_DIR);
    exe_path.push(&gen_pdf_file_name(id));
    exe_path
}

fn get_font_path() -> PathBuf {
    let mut exe_path = env::current_exe().unwrap();
    let _ = exe_path.pop();
    exe_path.push(FONT_DIR);
    exe_path
}

pub fn generate_pdf(id: u64, cpe: &str, data: CPEResponse) -> Result<String, Box<dyn Error + Send>> {
    let default_font =
        fonts::from_files(get_font_path(), DEFAULT_FONT_NAME, None)
            .expect("Failed to load the default font family");

    let mut doc = genpdf::Document::new(default_font);
    let mut decorator = genpdf::SimplePageDecorator::new();
    decorator.set_margins(10);
    decorator.set_header(|page| {
        let mut layout = elements::LinearLayout::vertical();
        if page > 1 {
            layout.push(
                elements::Paragraph::new(format!("Page {}", page)).aligned(genpdf::Alignment::Center),
            );
            layout.push(elements::Break::new(1));
        }
        layout.styled(style::Style::new().with_font_size(10))
    });
    doc.set_page_decorator(decorator);


    let title = format!("Vulnerability information for {}", cpe);
    doc.set_title(&title);
    doc.set_minimal_conformance();
    doc.set_line_spacing(1.25);

    doc.push(
        genpdf::elements::Paragraph::default()
        .styled_string(title, style::Style::new()
            .with_font_size(16))
        .aligned(genpdf::Alignment::Center)
        .padded(5)
    );

    let mut table = elements::TableLayout::new(vec![2, 3, 2, 3]);
    table.set_cell_decorator(elements::FrameCellDecorator::new(true, true, false));

    table
    .row()
    .element(
        elements::Paragraph::new("CVE-id")
            .styled(style::Effect::Bold)
            .padded(1),
    )
    .element(
        elements::Paragraph::new("Description")
            .styled(style::Effect::Bold)
            .padded(1),
    )
    .element(
        elements::Paragraph::new("CVSS")
            .styled(style::Effect::Bold)
            .padded(1),
    )
    .element(
        elements::Paragraph::new("Link")
            .styled(style::Effect::Bold)
            .padded(1),
    )
    .push()
    .expect("Invalid table row");

    for item in data.vulnerabilities {

        // Description
        let mut description = &"Description unavailable".to_owned();
        for desc in &item.cve.descriptions {
            if desc.lang == "en" {
                description = &desc.value;
                break;
            }
        }

        // CVSS
        let none_str = "None".to_owned();
        let base_severity = item.cve.get_base_severity().unwrap_or(&none_str);
        let base_score = match item.cve.get_cvss_base_score() {
            Some(score) => format!("{}", score.to_string()),
            None => format!("Base score unavailable")
        };
        
        // Link
        let link = format!("https://nvd.nist.gov/vuln/detail/{}", &item.cve.id);


        let list_layout = elements::LinearLayout::vertical()
            .element(elements::Paragraph::new(format!("Severity: {}", base_severity)).padded(1))
            .element(elements::Paragraph::new(format!("Base Score: {}", base_score)).padded(1));

        table
            .row()
            .element(elements::Paragraph::new(format!("{}", &item.cve.id)).padded(1))
            .element(elements::Paragraph::new(format!("{}", description)).padded(1))
            .element(list_layout.padded(1))
            .element(
                elements::Paragraph::default()
                .styled_string(format!("{}", &link), style::Style::new()
                    .with_font_size(7))
                .aligned(genpdf::Alignment::Center)
            )
            .push()
            .expect("Invalid table row");
    }

    doc.push(table.padded(3));

    let output_file = get_pdf_file_path(id);
    doc.render_to_file(&output_file)
        .expect("Failed to write output file");

    Ok(output_file.to_str().unwrap().to_owned())
}