package ctl

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"github.com/sigstore/fulcio/pkg/log"
	"io/ioutil"
	"net/http"
	"strings"
)

var ct_url = "http://127.0.0.1:8080/test/ct/v1/add-chain"

type certChain struct {
	Chain []string `json:"chain"`
}

type certChainResponse struct {
	SctVersion int    `json:"sct_version"`
	ID         string `json:"id"`
	Timestamp  int64  `json:"timestamp"`
	Extensions string `json:"extensions"`
	Signature  string `json:"signature"`
}

func AddChain(root string, clientcert []string)  {
	// Build the PEM Chain {root, client}
	rootblock, _ := pem.Decode([]byte(root))
	clientblock, _ := pem.Decode([]byte(strings.Join(clientcert,", ")))
	chainjson := &certChain{Chain: []string{base64.StdEncoding.EncodeToString(rootblock.Bytes), base64.StdEncoding.EncodeToString(clientblock.Bytes)}}
	jsonStr, _ := json.Marshal(chainjson)

	// Send to add-chain on CT log
	req, err := http.NewRequest("POST", ct_url, bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)


	var ctlresp certChainResponse
	err = json.Unmarshal(body, &ctlresp)
	if err != nil {
		log.Logger.Fatal(err)
	}
	log.Logger.Info("CT Submission ID: ", ctlresp.ID)
	log.Logger.Info("CT Submission TIMESTAMP: ", ctlresp.Timestamp)
	log.Logger.Info("CT Submission Signature: ", ctlresp.Signature)

	//log.Logger.Info("CT Response Status:", resp.Status)
	//log.Logger.Info("response Body:", string(body))

}