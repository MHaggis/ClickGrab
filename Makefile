.PHONY: install test run-cli run-ui

install:
	pip install -r requirements.txt

test:
	python test_pydantic.py

run-cli:
	python clickgrab_pydantic.py $(URL) $(ARGS)

run-ui:
	streamlit run streamlit_app.py

clean:
	rm -rf reports/ temp_reports/ latest_consolidated_report.json 