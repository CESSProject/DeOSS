package handler

var content_captcha = `<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <title>Please check your captcha</title>
</head>

<body>
	<div>
		<includetail>
			<div align="center">
				<div class="open_email" style="margin-left: 8px; margin-top: 8px; margin-bottom: 8px; margin-right: 8px;">
					<div>
						<br>
						<span class="genEmailContent">
							<div id="cTMail-Wrap"
								 style="word-break: break-all;box-sizing:border-box;text-align:center;min-width:320px; max-width:660px; border:1px solid #f6f6f6; background-color:#f7f8fa; margin:auto; padding:20px 0 30px; font-family:'helvetica neue',PingFangSC-Light,arial,'hiragino sans gb','microsoft yahei ui','microsoft yahei',simsun,sans-serif">
								<div class="main-content" style="">
									<table style="width:100%;font-weight:300;margin-bottom:10px;border-collapse:collapse">
										<tbody>
										<tr style="font-weight:300">
										
											<td style="width:3%;max-width:30px;"></td>
											
											<td style="max-width:600px;">
												<div id="cTMail-logo">
													<a href="">
														<img border="0" src="https://raw.githubusercontent.com/CESSProject/W3F-illustration/2973b1f85d9fecd74ee03f5cb8ba40a2c107ba8a/gateway/CESS%20%20vector.svg"
															 style="width:126px; height:70px;display:block">
													</a>
												</div>

												<div id="cTMail-inner" style="background-color:#fff; padding:23px 0 20px;box-shadow: 0px 1px 1px 0px rgba(122, 55, 55, 0.2);text-align:left;">
													<table style="width:100%;font-weight:300;margin-bottom:0px;border-collapse:collapse;text-align:left;">
														<tbody>
														
														<tr style="font-weight:300">
														<td style="max-width:480px;text-align:left;">
																<p id="cTMail-userName" style="font-size:18px; font-weight: bold; color:#333; line-height:24px; margin:0;">
																	Hey, Here's your captcha:
																</p><br>
																{{.Captcha}}
																<br><br>
																validity: 5 minutes
																<br><br><br><br>
																<p style="font-size:12px;">If this is not your action, please ignore and close this message.</p>
																<p style="font-size:12px;">This is a system email, please do not reply.</p>
															</td>
															
														</tr>
														
														</tbody>
													</table>
												</div>

												<div id="cTMail-copy" style="text-align:center; font-size:12px; line-height:18px; color:#999">
													<table style="width:100%;font-weight:300;margin-bottom:0px;border-collapse:collapse">
														<tbody>
														<tr style="font-weight:300">
															
															<td style="max-width:540px;">

																<p id="cTMail-rights" style="max-width: 100%; margin:auto;font-size:12px;color:#999;text-align:center;line-height:22px;">
																	<br>
																	Official website:
																	<a href="https://cess.cloud/">CESS</a>&nbsp;&nbsp;&nbsp;&nbsp;
																	Twitter:
																	<a href="https://twitter.com/CESS_Storage">CESS_Storage</a>

																	<br>
																	<img src="https://raw.githubusercontent.com/CESSProject/W3F-illustration/877e0cde92c3ca724f7a80ee7d0449d016fca265/gateway/2022%20%C2%A9%20Cumulus%20Encrypted%20Storage%20System%20(CESS).svg" style="margin-top: 10px;">
																</p>
															</td>
															
														</tr>
														</tbody>
													</table>
												</div>
											</td>
											<td style="width:3%;max-width:30px;"></td>
										</tr>
										
										</tbody>
									</table>
								</div>
							</div>
						</span>
					</div>
				</div>
			</div>
		</includetail>
	</div>
</body>
</html>`

var content_token = `<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <title>Please check your captcha</title>
</head>

<body>
	<div>
		<includetail>
			<div align="center">
				<div class="open_email" style="margin-left: 8px; margin-top: 8px; margin-bottom: 8px; margin-right: 8px;">
					<div>
						<br>
						<span class="genEmailContent">
							<div id="cTMail-Wrap"
								 style="word-break: break-all;box-sizing:border-box;text-align:center;min-width:320px; max-width:660px; border:1px solid #f6f6f6; background-color:#f7f8fa; margin:auto; padding:20px 0 30px; font-family:'helvetica neue',PingFangSC-Light,arial,'hiragino sans gb','microsoft yahei ui','microsoft yahei',simsun,sans-serif">
								<div class="main-content" style="">
									<table style="width:100%;font-weight:300;margin-bottom:10px;border-collapse:collapse">
										<tbody>
										<tr style="font-weight:300">
										
											<td style="width:3%;max-width:30px;"></td>
											
											<td style="max-width:600px;">
												<div id="cTMail-logo">
													<a href="">
														<img border="0" src="https://raw.githubusercontent.com/CESSProject/W3F-illustration/2973b1f85d9fecd74ee03f5cb8ba40a2c107ba8a/gateway/CESS%20%20vector.svg"
															 style="width:126px; height:70px;display:block">
													</a>
												</div>

												<div id="cTMail-inner" style="background-color:#fff; padding:23px 0 20px;box-shadow: 0px 1px 1px 0px rgba(122, 55, 55, 0.2);text-align:left;">
													<table style="width:100%;font-weight:300;margin-bottom:0px;border-collapse:collapse;text-align:left;">
														<tbody>
														
														<tr style="font-weight:300">
														<td style="max-width:480px;text-align:left;">
																<p id="cTMail-userName" style="font-size:18px; font-weight: bold; color:#333; line-height:24px; margin:0;">
																	Hey, Here's your token:
																</p><br>
																{{.Token}}
																<br><br>
																validity: 1 month
																<br><br><br><br>
																<p style="font-size:12px;">If this is not your action, your email may have been stolen, please change your password as soon as possible.</p>
																<p style="font-size:12px;">This is a system email, please do not reply.</p>
															</td>
															
														</tr>
														
														</tbody>
													</table>
												</div>

												<div id="cTMail-copy" style="text-align:center; font-size:12px; line-height:18px; color:#999">
													<table style="width:100%;font-weight:300;margin-bottom:0px;border-collapse:collapse">
														<tbody>
														<tr style="font-weight:300">
															
															<td style="max-width:540px;">

																<p id="cTMail-rights" style="max-width: 100%; margin:auto;font-size:12px;color:#999;text-align:center;line-height:22px;">
																	<br>
																	Official website:
																	<a href="https://cess.cloud/">CESS</a>&nbsp;&nbsp;&nbsp;&nbsp;
																	Twitter:
																	<a href="https://twitter.com/CESS_Storage">CESS_Storage</a>

																	<br>
																	<img src="https://raw.githubusercontent.com/CESSProject/W3F-illustration/877e0cde92c3ca724f7a80ee7d0449d016fca265/gateway/2022%20%C2%A9%20Cumulus%20Encrypted%20Storage%20System%20(CESS).svg" style="margin-top: 10px;">
																</p>
															</td>
															
														</tr>
														</tbody>
													</table>
												</div>
											</td>
											<td style="width:3%;max-width:30px;"></td>
										</tr>
										
										</tbody>
									</table>
								</div>
							</div>
						</span>
					</div>
				</div>
			</div>
		</includetail>
	</div>
</body>
</html>`
