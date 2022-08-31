import React, { Component } from 'react';
import { Modal } from "react-bootstrap";
import Form from "react-jsonschema-form";
import PropTypes from 'prop-types';
import _ from 'lodash';
import ApiHelper from "../../../util/ApiHelper";

class RatinggroupQuotaModal extends Component {
  // constructor(props) {
  //   super(props);

  //   (async () => {
  //     // this.propTypes
  //     console.log("props", props)
  //     let quotadata = await ApiHelper.fetchQuota(props.quota["supi"]);
  //     this.schema.properties.quota.default = quotadata["quota"]
  //   })();
  //   // this.schema.properties.quota.default = ApiHelper.fetchQuota();
  // }
  
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
    // title: "A registration form",
    // "description": "A simple form example.",
    type: "object",
    required: [
      // "supi",
      "quota",
    ],
    properties: {
      // supi: {
      //   type: "string",
      //   title: "Supi",
      //   // default: this.state.formData["supi"],
      // },
      quota: {
        type: "integer",
        title: "Ratinggroup Quota (Bytes)",
        default: 1000000000,
        maximum: 2000000000,
        minimum: 0
      },
    },
  };
  // async componentDidUpdate(prevProps, prevState, snapshot) {
  //   let quota_temp = await ApiHelper.fetchQuota()["quota"]
  //   console.log("quota in component:", quota_temp)

  //   this.schema.properties.quota.default = quota_temp;
  // }

  // componentDidMount() {
  //   console.log("componentDidMount", this.props.quota)
  //   if (this.props.quota) {
  //     let formData = {
  //       quota: this.props.quota['quota'],
  //     };

  //     this.setState({
  //           formData: formData,
  //     });
  //   }
  // }

  componentDidUpdate(prevProps, prevState, snapshot) {
    console.log("componentDidUpdate", this.props.quota, "prevProps", prevProps)

    if (prevProps !== this.props) {
      // this.setState({ editMode: !!this.props.quota });

      if (prevProps && prevProps.quota && this.props.quota && prevProps.quota['supi'] == this.props.quota['supi'])
        return

      if (this.props.quota) {
        let formData = {
          quota: this.props.quota['quota'],
        };

        this.setState({
              formData: formData,
        });

      }
    }
  }

  async onChange(data) {
    console.log("onChange")

    this.setState({
      formData: data.formData,
    });
  }

  // async updateFormData(newData) {
  //   console.log("updateFormData")

  //   // Workaround for bug: https://github.com/rjsf-team/react-jsonschema-form/issues/758
  //   await this.setState({ rerenderCounter: this.state.rerenderCounter + 1 });
  //   // await this.setState({
  //   //   rerenderCounter: this.state.rerenderCounter + 1,
  //   //   formData: newData,
  //   // });
  // }

  onSubmitClick(result) {
    // console.log("onSubmitClick")

    const formData = result.formData;

    let quotaData = {
      "quota": formData["quota"],
      "supi": formData["supi"],
    };

    this.props.onModify(quotaData);
  }

  render() {
    return (
      <Modal
        show={this.props.open}
        className={"fields__edit-modal theme-light"}
        backdrop={"static"}
        onHide={this.props.setOpen.bind(this, false)}>
        <Modal.Header closeButton>
          <Modal.Title id="example-modal-sizes-title-lg">
            Edit Quota
          </Modal.Title>
        </Modal.Header>

        <Modal.Body>
          {
            <Form schema={this.schema}
              formData={this.state.formData}
              onChange={this.onChange.bind(this)}
              onSubmit={this.onSubmitClick.bind(this)} />
          }
        </Modal.Body>
      </Modal>
    );

  }
}

export default RatinggroupQuotaModal;
