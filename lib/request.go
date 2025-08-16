package conhoslib

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
)

type RequestParams struct {
	Url     string
	Method  string
	Headers map[string]string
}

func Request(params RequestParams) ([]byte, *Error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{
		Transport: transport,
	}

	req, err := http.NewRequest(params.Method, params.Url, nil)
	if err != nil {
		return []byte(""), NewError(err.Error())
	}

	for name, value := range params.Headers {
		req.Header.Set(name, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return []byte(""), NewError(err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return body, NewError(fmt.Sprintf("status code is not OK, %d", resp.StatusCode))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return []byte(""), NewError(err.Error())
	}

	return body, nil
}
