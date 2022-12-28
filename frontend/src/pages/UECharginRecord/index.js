import React, { Component } from "react";
import { Button } from "react-bootstrap";
import { Link, withRouter } from "react-router-dom";
import { BootstrapTable, TableHeaderColumn } from "react-bootstrap-table";
import { connect } from "react-redux";
import UEInfoApiHelper from "../../util/UEInfoApiHelper";
import RatinggroupQuotaModal from "./components/RatinggroupQuotaModal";
import ApiHelper from "../../util/ApiHelper";

class DetailButton extends Component {
  constructor(props) {
    super(props);
    this.handleClick = this.handleClick.bind(this);
  }

  handleClick(cell, row, rowIndex) {
    UEInfoApiHelper.fetchUEInfoDetail(cell).then((result) => {
      let success = result[0];
      let smContextRef = result[1];

      if (success) {
        // console.log("After fetchUEInfoDetail")
        // console.log(smContextRef)
        UEInfoApiHelper.fetchUEInfoDetailSMF(smContextRef).then();
      }
    });
  }

  render() {
    const { cell, row, rowIndex } = this.props;
    return (
      <Button
        bsStyle="primary"
        onClick={() => this.handleClick(cell, row, rowIndex)}
      >
        <Link to={`/ueinfo/${cell}`}>Show Info</Link>
      </Button>
    );
  }
}

class UECharginRecord extends Component {
  state = {
    quotaModalOpen: false,
    quotaModalData: null,
  };

  componentDidMount() {
    UEInfoApiHelper.fetchUEWithCR().then(() => {
      // console.log("After fetchRegisteredUE")
      // console.log(this.props.get_registered_ue_err)
    });

    this.interval = setInterval(async () => {
      await UEInfoApiHelper.fetchUEWithCR();
    }, 1000);
  }

  componentWillUnmount() {
    clearInterval(this.interval);
  }

  refreshTable() {
    UEInfoApiHelper.fetchUEWithCR().then();
  }

  async openEditQuota(cell) {
    console.log("openEditQuota");

    const quota = await ApiHelper.fetchQuota(cell);
    console.log("fetchquota supi", quota["supi"]);

    this.setState({
      quotaModalOpen: true,
      quotaModalData: quota,
    });
    console.log(this.state.quotaModalData);
  }

  async addQuota(subscriberData) {
    console.log("addQuota");
    this.setState({ subscriberModalOpen: false });

    if (!(await ApiHelper.createSubscriber(subscriberData))) {
      alert("Error creating new q when create user");
    }
    ApiHelper.fetchQuota().then();
  }

  async updateQuota(quotaData) {
    console.log(
      "updateQuota   quotadata:",
      quotaData,
      "this.state.quotaModalData",
      this.state.quotaModalData
    );
    this.setState({ quotaModalOpen: false });

    let newquotaData = this.state.quotaModalData;
    newquotaData["quota"] = quotaData["quota"];
    this.setState({ quotaModalData: newquotaData });
    console.log("after updateQuota:", this.state.quotaModalData);

    const result = await ApiHelper.updateQuota(newquotaData);

    if (!result) {
      alert("Error updating quota: " + newquotaData["quota"]);
    }
    ApiHelper.fetchQuota(newquotaData["supi"]).then();
  }

  cellButton(cell, row, enumObject, rowIndex) {
    return <DetailButton cell={cell} row={row} rowIndex={rowIndex} />;
  }

  rowStyleFormat(cell, row, enumObject, rowIndexx) {
    // console.log("In rowStyleFormat")
    // console.log(cell)

    if (cell.Status === "Registered") {
      return { backgroundColor: "#4CBB17" };
    } else if (cell.Status === "Disconnected") {
      return { backgroundColor: "#CD5C5C" };
    }
    //return { backgroundColor: rowIndexx % 2 === 0 ? 'red' : 'blue' };
  }

  // const defaultSortedBy = [{
  //   dataField: "name",
  //   order: "asc"  // or desc
  // }];

  render() {
    return (
      <div className="content">
        <div className="container-fluid">
          <div className="dashboard__title">
            <h2>Real Time Status with Charging Record</h2>
            <Button
              bsStyle={"primary"}
              className="subscribers__button"
              onClick={this.refreshTable.bind(this)}
            >
              Refresh
            </Button>
          </div>
          <div className="row">
            <div className="col-12">
              {!this.props.get_ue_cr_err && (
                <BootstrapTable
                  data={this.props.users_cr}
                  striped={true}
                  hover={true}
                  pagination={
                    true
                  } /* defaultSorted={defaultSortedBy} pagination={ paginationFactory() }/*trStyle={this.rowStyleFormat.bind(this)}*/
                >
                  <TableHeaderColumn
                    dataField="supi"
                    width="15%"
                    isKey={true}
                    dataAlign="center"
                    dataSort={true}
                  >
                    SUPI
                  </TableHeaderColumn>
                  <TableHeaderColumn
                    dataField="status"
                    width="8%"
                    dataSort={true}
                  >
                    Status
                  </TableHeaderColumn>
                  <TableHeaderColumn
                    dataField="supi"
                    width="8%"
                    dataFormat={this.cellButton.bind(this)}
                  >
                    Details
                  </TableHeaderColumn>
                  <TableHeaderColumn
                    dataField="supi"
                    width="14%"
                    dataFormat={(cell, row, rowIndex, formatExtraData) => {
                      return (
                        <Button
                          bsStyle={"primary"}
                          className="subscribers__button"
                          onClick={this.openEditQuota.bind(this, cell)}
                        >
                          Modify RatinggroupQuota
                        </Button>
                      );
                    }}
                  >
                    Modify quota
                  </TableHeaderColumn>
                  <TableHeaderColumn
                    dataField="quotaLeft"
                    width="13%"
                    dataSort={true}
                  >
                    Quota Left
                  </TableHeaderColumn>
                  <TableHeaderColumn
                    dataField="totalVol"
                    width="14%"
                    dataSort={true}
                  >
                    Data Total Volume &#40;KB&#41;{" "}
                  </TableHeaderColumn>
                  <TableHeaderColumn
                    dataField="ulVol"
                    width="14%"
                    dataSort={true}
                  >
                    Data Volume Uplink &#40;KB&#41;
                  </TableHeaderColumn>
                  <TableHeaderColumn
                    dataField="dlVol"
                    width="14%"
                    dataSort={true}
                  >
                    Data Volume Downlink &#40;KB&#41;
                  </TableHeaderColumn>
                </BootstrapTable>
              )}
            </div>
            <div className="col-12">
              {this.props.get_ue_cr_err && <h2>{this.props.ue_cr_err_msg}</h2>}
            </div>
          </div>
          <RatinggroupQuotaModal
            open={this.state.quotaModalOpen}
            setOpen={(val) => this.setState({ quotaModalOpen: val })}
            quota={this.state.quotaModalData}
            // quota={{quota: 7777, supi: 'imsi-208930000000003'}}

            onModify={this.updateQuota.bind(this)}
            onSubmit={this.addQuota.bind(this)}
          />
        </div>
      </div>
    );
  }
}

export default withRouter(
  connect((state) => ({
    users_cr: state.ueinfo.users_cr,
    get_ue_cr_err: state.ueinfo.get_ue_cr_err,
    ue_cr_err_msg: state.ueinfo.ue_cr_err_msg,
    smContextRef: state.ueinfo.smContextRef,
  }))(UECharginRecord)
);
