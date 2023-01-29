import React, { Component } from "react";
import { Modal } from "react-bootstrap";
import Form from "react-jsonschema-form";
import PropTypes from "prop-types";
import _ from "lodash";

class RatinggroupQuotaModal extends Component {
  static propTypes = {
    open: PropTypes.bool.isRequired,
    setOpen: PropTypes.func.isRequired,
    quota: PropTypes.object.isRequired,
    onModify: PropTypes.func.isRequired,
    onSubmit: PropTypes.func.isRequired,
  };

  state = {
    formData: undefined,
    editMode: false,
  };

  schema = {
    type: "object",
    required: [
      "quota",
    ],
    properties: {
      quota: {
        type: "integer",
        title: "Ratinggroup Quota",
        default: 1000000000,
        maximum: 2000000000,
        minimum: 0,
      },
    },
  };

  componentDidUpdate(prevProps, prevState, snapshot) {
    if (prevProps !== this.props) {
      // this.setState({ editMode: !!this.props.quota });

      if (
        prevProps &&
        prevProps.quota &&
        this.props.quota &&
        prevProps.quota["supi"] == this.props.quota["supi"]
      )
        return;

      if (this.props.quota) {
        let formData = {
          quota: this.props.quota["quota"],
        };

        this.setState({
          formData: formData,
        });
      }
    }
  }

  async onChange(data) {
    this.setState({
      formData: data.formData,
    });
  }


  onSubmitClick(result) {
    const formData = result.formData;

    let quotaData = {
      quota: formData["quota"],
      supi: formData["supi"],
    };

    this.props.onModify(quotaData);
  }

  render() {
    return (
      <Modal
        show={this.props.open}
        className={"fields__edit-modal theme-light"}
        backdrop={"static"}
        onHide={this.props.setOpen.bind(this, false)}
      >
        <Modal.Header closeButton>
          <Modal.Title id="example-modal-sizes-title-lg">
            Edit Quota
          </Modal.Title>
        </Modal.Header>

        <Modal.Body>
          {
            <Form
              schema={this.schema}
              formData={this.state.formData}
              onChange={this.onChange.bind(this)}
              onSubmit={this.onSubmitClick.bind(this)}
            />
          }
        </Modal.Body>
      </Modal>
    );
  }
}

export default RatinggroupQuotaModal;
