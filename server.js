// const express = require("express");
// const cors = require("cors");

// const app = express();

// var corsOptions = {
//   origin: "http://localhost:8081",
// };

// app.use(cors(corsOptions));

// // parse requests of content-type - application/json
// app.use(express.json());

// // parse requests of content-type - application/x-www-form-urlencoded
// app.use(express.urlencoded({ extended: true }));

// // simple route
// app.get("/", (req, res) => {
//   res.json({ message: "Welcome to bezkoder application." });
// });

// // set port, listen for requests
// const PORT = process.env.PORT || 8080;
// app.listen(PORT, () => {
//   console.log(`Server is running on port ${PORT}.`);
// });

// const express = require("express");
// const app = express();
// const port = process.env.PORT || 3000;

// app.get("/", (req, res) => {
//   res.json({
//     success: true,
//   });
// });

// app.listen(port, () => {
//   console.log(`server is listening at localhost:${process.env.PORT}`);
// });

// const express = require("express");
// const app = express();
// // const api = require("./server/routes/index");
// const api = require("./src//index");
// app.use("/api", api);
// const port = 3001;
// const cors = require("cors");
// const bodyParser = require("body-parser");

// app.use(bodyParser.urlencoded({ extended: false }));
// app.use(cors());
// app.use(bodyParser.json());

// app.get("/", (req, res) => {
//   res.send("Hello World!");
// });

// app.post("/text", (req, res) => {
//   //데이터 받는 곳
//   const text1 = req.body.inText;
//   console.log(text1);
// });

// app.listen(port, () => {
//   console.log(`Example app listening at http://localhost:${port}`);
// });

// const express = require("express");
// const app = express();
// const PORT = process.env.PORT || 4000;
// const db = require("./config/dbconfig");

//221206_원래 되던것
// const express = require("express");
// const path = require("path");
// const app = express();
// app.use(express.json());
// var cors = require("cors");
// app.use(cors());
// app.listen(8080, function () {
//   console.log("listening on 8080");
// });

//항상 제일 밑

// app.use(express.static(path.join(__dirname, "./build")));

// app.get("/", function (요청, 응답) {
//   응답.sendFile(path.join(__dirname, "./build/index.html"));
// });

// // url 입력하면 서버로 가장 하단
// app.get("*", function (요청, 응답) {
//   응답.sendFile(path.join(__dirname, "./build/index.html"));
// });

// app.get('/api/meal', (req, res) => {
//   sql = `select meal from school';

//   db.query(sql, (err, data) => {
//       if(!err) res.send({ products : data });
//       else res.send(err);
//   })
// })

// 221206;

// Import the necessary modules
// import mysql from "mysql";
// import express from "express";
// import React from "react";
// import axios from "axios";
// import { renderToString } from "react-dom/server";

// // Set up the Express app
// const app = express();

// // Connect to the database
// const cnx = mysql.createConnection({
//   host: "localhost",
//   user: "jjw3310",
//   password: "Dev2022@",
//   database: "mysql",
// });

// // Set up a route that will handle the incoming request
// app.get("/", (req, res) => {
//   // Execute a SQL query
//   const query = "SELECT * FROM your_table";
//   cnx.query(query, (err, results) => {
//     if (err) {
//       // If an error occurs, send an error message as the response
//       res
//         .status(500)
//         .send("An error occurred while retrieving data from the database");
//       return;
//     }

//     // Use React to render the component on the server
//     const App = (
//       <ul>
//         {results.map((result) => (
//           <li key={result.id}>{result.name}</li>
//         ))}
//       </ul>
//     );
//     const html = renderToString(App);

//     // Send the rendered HTML as the response
//     res.send(html);
//   });
// });

// // Set up a route that will make an API request using Axios
// app.get("/api/data", (req, res) => {
//   axios
//     .get("https://example.com/api/data")
//     .then((response) => {
//       // Use the data from the API response in your app
//       const data = response.data;
//       const App = <h1>{data.title}</h1>;
//       const html = renderToString(App);

//       // Send the rendered HTML as the response
//       res.send(html);
//     })
//     .catch((error) => {
//       // Handle any errors
//       console.error(error);
//       res.status(500).send("An error occurred while making the API request");
//     });
// });

// import db from "@config/dbconfig";
// import express from "express";
// import mysql from "mysql";
// import jwt from "jsonwebtoken";
const jwt = require("jsonwebtoken");
const express = require("express");
// const session = require("express-session");
// const uuid = require("uuid/v4");
const path = require("path");
const mysql = require("mysql");
const Web3 = require("web3");
const bodyParser = require("body-parser");
const { urlencoded } = require("body-parser");
const dbconfig = require("./src/config/dbconfig.js");
const db = mysql.createConnection(dbconfig);
// 잘 연동 되었는지 확인
db.connect(function (err) {
  if (err) throw err;
  console.log("DB is Connected!");
});

// const jwt = require("jsonwebtoken");
require("dotenv").config();
const cookie = require("cookie");
// const multer = require("multer");
const app = express();
app.use(express.json());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
const JWT_SECRET = "your-secret-key";
const JWT_EXPIRY_TIME = 24 * 3600 * 1000; // 24시간

app.use(express.json());
var cors = require("cors");
app.use(cors());
const port = 8080;
const bcrypt = require("bcrypt");
const saltRounds = 10;
// app.post("/login", (req, res) => {
//   const { email, password } = req.body;

//   // 이곳에서 이메일과 암호를 검증하고 검증 성공 시 아래의 코드 실행
//   const accessToken = jwt.sign({ email }, JWT_SECRET, {
//     expiresIn: JWT_EXPIRY_TIME / 1000, // expiresIn 옵션은 초 단위이므로 1000으로 나눠줍니다.
//   });
//   res.send({ accessToken });
// });

// app.post("/silent-refresh", (req, res) => {
//   const { accessToken } = req.body;

//   try {
//     // 토큰 검증
//     const { email } = jwt.verify(accessToken, JWT_SECRET);

//     // 유효한 토큰이면 새로운 토큰 발급
//     const newAccessToken = jwt.sign({ email }, JWT_SECRET, {
//       expiresIn: JWT_EXPIRY_TIME / 1000,
//     });
//     res.send({ accessToken: newAccessToken });
//   } catch (error) {
//     // 토큰이 유효하지 않으면 에러 응답
//     res.status(401).send({ message: "Unauthorized" });
//   }
// });
// app.use(
//   session({
//     secret: "my-secret-key",
//     genid: () => uuid(),
//   })
// );
// const Web3 = require("web3");
// const contract = require("@truffle/contract");
// const artifacts = require("./build/contracts/Contacts.json");
// const CONTACT_ABI = require("./config");
// const CONTACT_ADDRESS = require("./config");

// if (typeof web3 !== "undefined") {
//   var web3 = new Web3(web3.currentProvider);
// } else {
//   var web3 = new Web3(new Web3.providers.HttpProvider("http://localhost:8545"));
// }

// app.get("/", (req, res) => {
//   res.send("Hello World!");
// });

//유저
//컨텐츠
//
// app.post('/login', (req, res) => {
//   // Verify user credentials

//   // If user credentials are correct
//   if (/* user credentials are correct */) {
//     // Generate login register session token
//     const token = uuid();

//     // Save token to user session
//     req.session.token = token;

//     // Send token to React frontend
//     res.json({ token });
//   } else {
//     // Send error message if user credentials are incorrect
//     res.status(401).send('Incorrect username or password');
//   }
// });
// app.get("/", (req, res) => {
//   const sql = "select * from new_table";

//   db.query(sql, function (err, result, field) {
//     // if (err) throw err;
//     // console.log(result);
//     // // const sendAllReview = result.filter((result) => {
//     // //   return result.hotel_name == requestHotelName;
//     // // });

//     // // console.log(sendAllReview);
//     // res.send(result);

//     if (err) {
//       // Handle the error
//       console.error(err);
//       res.status(500).send("An error occurred while running the query");
//     } else {
//       // Process the query results
//       console.log(result);
//       // res.send(result);
//       res.json(result);
//     }
//   });
//   // res.redirect("/");
//   // res.sendFile(path.join(__dirname, "./build/index.html"));
// });
// res.send(express.static(path.join(__dirname, "./build/index.html")));
// app.get("/auth", (req, res) => {
//   const sql = "select * from new_table";

//   db.query(sql, function (err, result, field) {
//     if (err) {
//       console.error(err);
//       res.status(500).send("An error occurred while running the query");
//     } else {
//       console.log(result);
//       res.send(result);
//     }
//   });
// });

// app.use(bodyParser.urlencoded({ extended: true }));
// app.get("/", (req, res) => {
//   const sql = "select * from new_table";

//   db.query(sql, function (err, result, field) {
//     if (err) {
//       // Handle the error
//       console.error(err);
//       res.status(500).send("An error occurred while running the query");
//     } else {
//       // Process the query results
//       console.log(result);
//       // res.send(result);
//       res.json(result);
//     }
//   });
// });

// 세션 설정
const session = require("express-session");
const { redirect } = require("react-router-dom");

app.use(
  session({
    secret: "secret key",
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 1000 * 60 * 60,
    },
  })
);

// 인증 검사 미들웨어
const authCheck = (req, res, next) => {
  if (req.session.user) {
    // 인증된 경우
    next();
  } else {
    // 인증되지 않은 경우
    res.send({
      success: false,
      message: "Unauthorized",
    });
  }
};

// 인증된 사용자만 접근 가능한 페이지
app.get("/profile", authCheck, (req, res) => {
  res.send({
    success: true,
    user: req.session.user,
  });
});

// 로그아웃
app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error(err);
      res.send({
        success: false,
        message: err.message,
      });
      return;
    }

    res.send({
      success: true,
      message: "Logged out successfully",
    });
  });
});
app.post("/userauth", (req, res) => {
  // const param = { title: "React POST Request Example" };
  // username,
  // nick_name,
  // userid,
  // password,
  // phone_number,
  // useremail,
  // // u_addr,
  // flexCheck,
  const param = req.body;
  // const sql = `insert into new_table (user_id) values (?)`;
  // const sql = `INSERT INTO Users (id, password) VALUES (?, ?)`;
  const sql = `insert into USER(name, nick_name, id, password, phone_number,u_email)
  values(?,?,?,?,?,?);`;
  console.log(param.flexCheck);
  console.log(sql);
  console.log(param);
  console.log("cococo");
  // bcrypt.hash(param[0], saltRounds, (error, hash) => {
  //   param[0] = hash;
  bcrypt.hash(param.password, saltRounds, (err, hash) => {
    console.log(hash);
    // const Web3 = require("web3");
    const web3 = new Web3();

    // 회원 비밀번호 해쉬값
    // const passwordHash = '0x1234567890abcdef1234567890abcdef';
    const passwordHash = hash;
    console.log(hash);

    // 회원 비밀번호 해쉬값을 이용해서 metamask 주소 생성
    // const address = web3.eth.accounts.privateKeyToAccount(passwordHash).address;
    // const address = async () => {
    //   await web3.eth.accounts.privateKeyToAccount(
    //     "0x348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8709"
    //   ).address;
    // };
    // let result;
    // const address = async () => {
    //   result = await web3.eth.accounts.privateKeyToAccount(
    //     "0x348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8709"
    //   );
    // };
    // address();
    let result;
    const address = async () => {
      result = await web3.eth.accounts.create(
        "2435@#@#@±±±±!!!!678543213456764321§34567543213456785432134567"
      );
    };
    address();

    console.log("hello", result); // "0x1234567890abcdef1234567890abcdef12345678"
    db.query(
      sql,
      [
        param.username,
        param.nick_name,
        param.userid,
        hash,
        param.phone_number,
        param.useremail,
      ],
      (err, result) => {
        if (err) {
          // 쿼리를 실행하는 도중에 오류가 발생했을 때 처리할 코드
          res.send({
            success: false,
            message: err.message,
          });
          console.log(err);
        } else {
          // 쿼리 실행이 완료된 후 결과를 확인하는 코드
          if (result.affectedRows > 0) {
            // 쿼리가 정상적으로 실행되고 데이터가 추가된 경우
            res.send({
              success: true,
              message: "Data added successfully!",
            });
          } else {
            // 쿼리가 정상적으로 실행되지만 데이터가 추가되지 않은 경우
            res.send({
              success: false,
              message: "Data was not added. Please try again.",
            });
          }
        }

        // });
        // res.end();
      }
    );
  });
});

// app.post("/userauth", (req, res) => {
//   // const param = { title: "React POST Request Example" };
//   // username,
//   // nick_name,
//   // userid,
//   // password,
//   // phone_number,
//   // useremail,
//   // // u_addr,
//   // flexCheck,
//   const param = req.body;

//   // const sql = `insert into new_table (user_id) values (?)`;
//   // const sql = `INSERT INTO Users (id, password) VALUES (?, ?)`;

//   bcrypt.hash(param.password, saltRounds, (err, hash) => {
//     if (err) {
//       // 쿼리를 실행하는 도중에 오류가 발생했을 때 처리할 코드
//       res.send({
//         success: false,
//         message: err.message,
//       });
//       return;
//     }
//     // bcrypt.hash(param[0], saltRounds, (error, hash) => {
//     //   param[0] = hash;
//     const sql = `insert into USER(name, nick_name, id, password, phone_number,u_email)
//     values(?,?,?,?,?,?);`;
//     console.log(param.flexCheck);
//     console.log(sql);
//     console.log(param);
//     console.log("cococo");
//     db.query(
//       sql,
//       [
//         param.username,
//         param.nick_name,
//         param.userid,
//         hash,
//         param.phone_number,
//         param.useremail,
//       ],
//       (err, result) => {
//         if (err) {
//           // 쿼리를 실행하는 도중에 오류가 발생했을 때 처리할 코드
//           res.send({
//             success: false,
//             message: err.message,
//           });
//           return;
//         } else {
//           // 쿼리 실행이 완료된 후 결과를 확인하는 코드
//           if (result.affectedRows > 0) {
//             // 쿼리가 정상적으로 실행되고 데이터가 추가된 경우
//             res.send({
//               success: true,
//               message: "Data added successfully!",
//             });
//           } else {
//             // 쿼리가 정상적으로 실행되지만 데이터가 추가되지 않은 경우
//             res.send({
//               success: false,
//               message: "Data was not added. Please try again.",
//             });
//           }
//         }
//         // });
//         // res.end();
//       }
//     );
//   });
// });
// 회원가입 API
// app.post("/userauth", (req, res) => {
//   const param = req.body;
//   console.log(param.password);
//   // 암호화 수행
//   bcrypt.hash(param.password, saltRounds, (err, hash) => {
//     console.log(hash);
//     if (err) {
//       // 쿼리를 실행하는 도중에 오류가 발생했을 때 처리할 코드
//       res.send({
//         success: false,
//         message: err.message,
//       });
//       return;
//     }

//     const sql = `insert into USER(name, nick_name, id, password, phone_number, u_email)
//     values(?,?,?,?,?,?)`;

//     db.query(
//       sql,
//       [
//         param.username,
//         param.nick_name,
//         param.userid,
//         hash,
//         param.phone_number,
//         param.useremail,
//       ],
//       (err, result) => {
//         if (err) {
//           // 쿼리를 실행하는 도중에 오류가 발생했을 때 처리할 코드
//           res.send({
//             success: false,
//             message: err.message,
//           });
//           return;
//         }

//         // 쿼리 실행이 완료된 후 결과를 확인하는 코드
//         if (result.affectedRows > 0) {
//           // 쿼리가 정상적으로 실행되고 데이터가 추가된 경우
//           res.send({
//             success: true,
//             message: "Data added successfully!",
//           });
//         } else {
//           // 쿼리가 정상적으로 실행되지만 데이터가 추가되지 않은 경우
//           res.send({
//             success: false,
//             message: "Data was not added. Please try again.",
//           });
//         }
//       }
//     );
//   });
// });
// 로그인 API
app.post("/logincheck", (req, res) => {
  const { id, password } = req.headers;

  // 사용자 정보 조회 쿼리
  const sql = `SELECT * FROM USER WHERE id = ?`;
  console.log(sql);
  db.query(sql, [id], (err, result) => {
    if (err) {
      res.send({
        success: false,
        message: err.message,
      });
      return;
    }

    // 사용자 정보가 조회되지 않은 경우
    if (result.length === 0) {
      res.send({
        success: false,
        message: "User not found",
      });
      return;
    }

    // 암호가 일치하는지 확인
    bcrypt.compare(password, result[0].password, (error, isMatch) => {
      if (error) {
        res.send({
          success: false,
          message: error.message,
        });
        return;
      }

      // 암호가 일치하는 경우
      if (isMatch) {
        // 세션 저장 및 응답 전송
        req.session.user = result[0];
        res.send({
          success: true,
          message: "Logged in successfully",
        });
        console.log(req.session.user);
        res.redirect("/");
      } else {
        // 암호가 일치하지 않는 경우
        res.send({
          success: false,
          message: "Incorrect password",
        });
        res.redirect("/login");
      }
    });
  });
});
// app.post("/api/member", (req, res) => {
//   const { userName, userId, userPassword, birthday, gender, eMail } = req.body;
//   console.log("name :", userName);
//   console.log("name :", userId);
//   console.log("name :", userPassword);
//   console.log("name :", birthday);
//   console.log("name :", gender);
//   console.log("name :", eMail);

//   const sql =
//     "INSERT INTO User(userName,userId, userPassword,birthday,gender, eMail) VALUES(?,?,?,?,?,?)";
//   const params = [userName, userId, userPassword, birthday, gender, eMail];
//   db.query(sql, params, (err, rows, fields) => {
//     if (err) {
//       console.log(err);
//     } else {
//       console.log(rows);
//     }
//   });
// });

// app.post("/login", (req, res) => {
//   const { id, password } = req.body;
//   console.log(id);
//   console.log(password);

//   // Verify the email and password against the database
//   db.query(
//     "SELECT * FROM user WHERE id = ? AND password = ?",
//     [id, password],
//     (error, results) => {
//       if (error) {
//         console.error(error);
//         res.status(500).json({ error: "Internal server error" });
//       } else if (results.length === 0) {
//         res.status(401).json({ error: "Invalid email or password" });
//       } else {
//         const user = results[0];

//         // Generate a JWT token
//         const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
//           expiresIn: "1h",
//         });
//         console.log(token);

//         // Send the token to the client
//         res.json({ token });
//       }
//     }
//   );
// });
//login
// app.post("/api/login", (req, res) => {
//   let isUser = false;
//   const { userId, userPassword } = req.body;
//   // console.log("name :", userId);
//   // console.log("name :", userPassword);
//   // console.log(req.headers.cookie);
//   var cookies = db.parse(req.headers.cookie);
//   console.log(cookies.user);

//   const sql = "SELECT userId, userPassword FROM User";
//   db.query(sql, (err, rows, fields) => {
//     if (err) {
//       console.log(err);
//     } else {
//       console.log(rows);
//       rows.forEach((info) => {
//         if (info.userId === userId && info.userPassword === userPassword) {
//           isUser = true;
//         } else {
//           return;
//         }
//       });
//       if (isUser) {
//         const YOUR_SECRET_KEY = process.env.SECRET_KEY;
//         const accessToken = jwt.sign(
//           {
//             userId,
//           },
//           YOUR_SECRET_KEY,
//           {
//             expiresIn: "1h",
//           }
//         );
//         res.cookie("user", accessToken);
//         res.status(201).json({
//           result: "ok",
//           accessToken,
//         });
//       } else {
//         res.status(400).json({ error: "invalid user" });
//       }
//     }
//   });
// });
//search app.get("/content/search?q=${q}")
//get app.get("/content/")
// get app.get("/contentedit")

app.get("/contentlist/:C_CA_NUM", (req, res) => {
  // app.get("/contentlist/", (req, res) => {
  const C_CA_NUM = parseInt(req.params.C_CA_NUM);
  console.log(C_CA_NUM);
  if (isNaN(C_CA_NUM)) {
    return res.status(400).send({ error: "Invalid C_CA_NUM parameter" });
  }
  const sqlQuery =
    // "SELECT a.* FROM (SELECT C_P_NUM, MAX(C_DATETIME) AS max_datetime FROM ontents GROUP BY C_P_NUM  ) AS b INNER JOIN contents AS a ON a.C_P_NUM = b.C_P_NUM AND a.C_DATETIME = b.max_datetime";
    // "SELECT a.* FROM ( SELECT C_P_NUM, MAX(C_DATETIME) AS max_datetime FROM contents WHERE C_P_NUM IN (SELECT C_P_NUM FROM contents GROUP BY C_P_NUM HAVING COUNT(*) > 1) GROUP BY C_P_NUM ) AS b INNER JOIN contents AS a ON a.C_P_NUM = b.C_P_NUM AND a.C_DATETIME = b.max_datetime UNION SELECT * FROM contents WHERE C_P_NUM NOT IN (SELECT C_P_NUM FROM contents WHERE C_P_NUM IN (SELECT C_P_NUM FROM contents GROUP BY C_P_NUM HAVING COUNT(*) > 1)) UNION SELECT * FROM contents WHERE C_P_NUM = 0 AND C_NUM NOT IN (SELECT C_NUM FROM contents WHERE C_P_NUM <> 0) ORDER BY C_DATETIME DESC";
    "SELECT a.* FROM ( SELECT C_P_NUM, MAX(C_DATETIME) AS max_datetime FROM contents WHERE C_P_NUM IN (SELECT C_P_NUM FROM contents GROUP BY C_P_NUM HAVING COUNT(*) > 1) GROUP BY C_P_NUM ) AS b INNER JOIN contents AS a ON a.C_P_NUM = b.C_P_NUM AND a.C_DATETIME = b.max_datetime AND a.C_CA_NUM = ? UNION SELECT * FROM contents WHERE C_P_NUM NOT IN (SELECT C_P_NUM FROM contents WHERE C_P_NUM IN (SELECT C_P_NUM FROM contents GROUP BY C_P_NUM HAVING COUNT(*) > 1)) AND C_CA_NUM = ? UNION SELECT * FROM contents WHERE C_P_NUM = 0 AND C_NUM NOT IN (SELECT C_NUM FROM contents WHERE C_P_NUM <> 0) AND C_CA_NUM = ? ORDER BY C_DATETIME DESC";
  console.log(sqlQuery);
  console.log("list");
  db.query(sqlQuery, [C_CA_NUM, C_CA_NUM, C_CA_NUM], (err, result) => {
    // db.query(sqlQuery, (err, result) => {
    res.send(result);
  });
});
// app.get("/contentlist", (req, res) => {
//   const sqlQuery = "SELECT * FROM simpleboard";
//   console.log(sqlQuery);
//   console.log("list");
//   db.query(sqlQuery, (err, result) => {
//     res.send(result);
//   });
// });
// app.get("/content/:C_NUM", (req, res) => {
//   const C_NUM = req.params.C_NUM;
//   console(C_NUM);
//   const sqlQuery = "SELECT * FROM simpleboard where C_NUM = (?)";
//   db.query(sqlQuery, (err, result) => {
//     res.send(result);
//   });
// });

// app.get("/contentlist/search", (req, res) => {
// app.get("/contents/search", (req, res) => {
//   // const query = req.params.puery;
//   // const id = req.query.id;
//   const query = req.query.query;
//   console.log(query);
//   console.log(query.query);
//   console.log(req.query.puery);
//   // const safeQuery = db.escape(query);
//   // console.log(safeQuery);
//   const changeQuery = "'%" + query + "%'";
//   console.log(changeQuery);
//   // console.log(query.puery);
//   // console.log(id);
//   const sqlQuery =
//     // "SELECT a.* FROM (SELECT C_P_NUM, MAX(C_DATETIME) AS max_datetime FROM ontents GROUP BY C_P_NUM  ) AS b INNER JOIN contents AS a ON a.C_P_NUM = b.C_P_NUM AND a.C_DATETIME = b.max_datetime";
//     // `x.C_NUM,x.C_TITLE,x.C_text,x.C_USER_NUM,x.C_USER_ADDR,x.C_DATETIME,x.C_CUT,x.C_P_NUM,x.C_TRANS,x.C_VIEW_CNT,x.C_SHARE_CNT,x.C_THUMBSUP_CNT,y.Co_NUM,y.Co_text,y.Co_USER_NUM,y.Co_C_P_NUM,y.Co_C_NUM,y.Co_COPY_CNT,y.Co_DATETIME,y.Co_del_yn,l.T_NUM,l.T_NAME,l.T_CA_NUM,l.T_del_yn,l.T_DATETIME,k.CA_NUM,k.CA_NAME,k.CA_del_yn,k.CA_DATETIME,(x.C_SHARE_CNT + y.Co_COPY_CNT + x.C_THUMBSUP_CNT) as pop from CONTENTS x join code y on x.C_NUM = y.Co_C_NUM join POST_TAG z on x.C_NUM = z.PC_C_NUM Join tag l on z.PC_T_NUM = l.T_NUM Join CATEGORY k	on l.T_CA_NUM = k.CA_NUM where x.C_TITLE	LIKE  ? OR x.C_text LIKE ? or l.T_NAME like ? or y.Co_text LIKE ? or k.CA_NAME like ?	and	x.C_del_yn = 'n' and k.CA_del_yn  = 'n' AND z.PC_del_yn = 'n'	and y.Co_del_yn = 'n'	and l.T_del_yn =  'n' order by pop desc`;
//     "select DISTINCT C_NUM, C_TITLE, C_DATETIME as pop from contents x join code y on x.C_NUM = y.Co_C_NUM join category k on x.C_CA_NUM = k.CA_NUM where x.C_TITLE LIKE ? OR x.C_text LIKE ? or y.Co_text LIKE ? or k.CA_NAME LIKE ? and x.C_del_yn = 'n' and k.CA_del_yn = 'n' order by C_DATETIME desc";
//   console.log(sqlQuery);
//   console.log("list");
//   db.query(
//     sqlQuery,
//     [
//       // "'%" + safeQuery + "%'",
//       // "'%" + safeQuery + "%'",
//       // "'%" + safeQuery + "%'",
//       // "'%" + safeQuery + "%'",
//       // "'%" + safeQuery + "%'",
//       changeQuery,
//       changeQuery,
//       changeQuery,
//       changeQuery,
//     ],
//     (err, result) => {
//       console.log(sqlQuery);
//       res.send(result);
//     }
//   );
// });
app.get("/contents/search", (req, res) => {
  const query = req.query.query;
  console.log(query);
  console.log(query.query);
  console.log(req.query.puery);
  const changeQuery = "%" + query + "%";
  // '%' + query + '%'
  console.log(changeQuery);
  const sqlQuery =
    "select DISTINCT C_NUM, C_TITLE, C_DATETIME, C_text from contents x join code y on x.C_NUM = y.Co_C_NUM join category k on x.C_CA_NUM = k.CA_NUM where x.C_TITLE LIKE (?) OR x.C_text LIKE (?) or y.Co_text LIKE (?) or k.CA_NAME LIKE (?) and x.C_del_yn = 'n' and k.CA_del_yn = 'n' order by C_DATETIME desc";
  console.log(sqlQuery);
  console.log("list");
  db.query(
    sqlQuery,
    [changeQuery, changeQuery, changeQuery, changeQuery],
    (err, result) => {
      console.log(sqlQuery);
      res.send(result);
    }
  );
});
// app.get("/contentlist/search", (req, res) => {
//   // Access the value of the query parameter
//   const query = req.query.query;
//   console.log(query);

//   // Use the % wildcard to match any number of characters before and after the search string
//   const sqlQuery =
//     "select x.C_NUM,x.C_TITLE,x.C_text,x.C_USER_NUM,x.C_USER_ADDR,x.C_DATETIME,x.C_CUT,x.C_P_NUM,x.C_TRANS,x.C_VIEW_CNT,x.C_SHARE_CNT,x.C_THUMBSUP_CNT,y.Co_NUM,y.Co_text,y.Co_USER_NUM,y.Co_C_P_NUM,y.Co_C_NUM,y.Co_COPY_CNT,y.Co_DATETIME,y.Co_del_yn,l.T_NUM,l.T_NAME,l.T_CA_NUM,l.T_del_yn,l.T_DATETIME,k.CA_NUM,k.CA_NAME,k.CA_del_yn,k.CA_DATETIME,(x.C_SHARE_CNT + y.Co_COPY_CNT + x.C_THUMBSUP_CNT) as pop from CONTENTS x join code y on x.C_NUM = y.Co_C_NUM join POST_TAG z on x.C_NUM = z.PC_C_NUM Join tag l on z.PC_T_NUM = l.T_NUM Join CATEGORY k	on l.T_CA_NUM = k.CA_NUM where x.C_TITLE LIKE ? OR x.C_text LIKE ? or l.T_NAME LIKE ? or y.Co_text LIKE ? or k.CA_NAME LIKE ? and x.C_del_yn = 'n' and k.CA_del_yn  = 'n' AND z.PC_del_yn = 'n' and y.Co_del_yn = 'n' and l.T_del_yn =  'n' order by pop desc";

//   // Pass the value of the query parameter as a variable, not a string
//   db.query(
//     sqlQuery,
//     [
//       "%" + query + "%",
//       "%" + query + "%",
//       "%" + query + "%",
//       "%" + query + "%",
//       "%" + query + "%",
//     ],
//     (err, result) => {
//       console.log(sqlQuery);
//       res.send(result);
//     }
//   );
// });
// app.get("/contentlist/search", (req, res) => {
//   // Access the value of the query parameter
//   const query = req.query.query;
//   console.log(query);
//   // Use the = operator instead of LIKE to match the search string exactly
//   const sqlQuery =
//     "select x.C_NUM,x.C_TITLE,x.C_text,x.C_USER_NUM,x.C_USER_ADDR,x.C_DATETIME,x.C_CUT,x.C_P_NUM,x.C_TRANS,x.C_VIEW_CNT,x.C_SHARE_CNT,x.C_THUMBSUP_CNT,y.Co_NUM,y.Co_text,y.Co_USER_NUM,y.Co_C_P_NUM,y.Co_C_NUM,y.Co_COPY_CNT,y.Co_DATETIME,y.Co_del_yn,l.T_NUM,l.T_NAME,l.T_CA_NUM,l.T_del_yn,l.T_DATETIME,k.CA_NUM,k.CA_NAME,k.CA_del_yn,k.CA_DATETIME,(x.C_SHARE_CNT + y.Co_COPY_CNT + x.C_THUMBSUP_CNT) as pop from CONTENTS x join code y on x.C_NUM = y.Co_C_NUM join POST_TAG z on x.C_NUM = z.PC_C_NUM Join tag l on z.PC_T_NUM = l.T_NUM Join CATEGORY k	on l.T_CA_NUM = k.CA_NUM where x.C_TITLE = ? OR x.C_text = ? or l.T_NAME = ? or y.Co_text = ? or k.CA_NAME = ? and x.C_del_yn = 'n' and k.CA_del_yn  = 'n' AND z.PC_del_yn = 'n' and y.Co_del_yn = 'n' and l.T_del_yn =  'n' order by pop desc";

//   // Pass the value of the query parameter as a variable, not a string
//   db.query(sqlQuery, [query, query, query, query, query], (err, result) => {
//     console.log(sqlQuery);
//     res.send(result);
//   });
// });

app.get("/content/:C_NUM", (req, res) => {
  // const idx = req.getParameter("C_NUM");
  // console.log(idx);
  const C_NUM = parseInt(req.params.C_NUM);
  console.log(C_NUM);
  if (isNaN(C_NUM)) {
    return res.status(400).send({ error: "Invalid C_NUM parameter" });
  }
  const sqlQuery = "SELECT * FROM contents where C_NUM = (?)";

  db.query(sqlQuery, [C_NUM], (err, result) => {
    if (err) {
      return res.status(500).send({ error: "Error executing query" });
    }
    res.send(result);
  });
});
app.get("/contentedit/:C_NUM", (req, res) => {
  // const idx = req.getParameter("C_NUM");
  // console.log(idx);
  const C_NUM = parseInt(req.params.C_NUM);
  console.log(C_NUM);
  if (isNaN(C_NUM)) {
    return res.status(400).send({ error: "Invalid C_NUM parameter" });
  }
  const sqlQuery =
    "SELECT *, (select count(C_NUM) from contents) as PRE_C_NUM  FROM contents where C_NUM = (?)";
  // const sqlQuery =
  //   "select * from CONTENTS inner join code on Co_C_NUM = C_NUM and Co_del_yn = 'n' WHERE C_NUM = (?) and C_del_yn = 'n' and C_TRANS = 1 ORDER BY C_DATETIME desc limit 0,1";

  db.query(sqlQuery, [C_NUM], (err, result) => {
    if (err) {
      return res.status(500).send({ error: "Error executing query" });
    }
    res.send(result);
  });
});
// app.get("/contentedit/:C_NUM", (req, res) => {
//   // const idx = req.getParameter("C_NUM");
//   // console.log(idx);
//   const C_NUM = parseInt(req.params.C_NUM);
//   console.log(C_NUM);
//   if (isNaN(C_NUM)) {
//     return res.status(400).send({ error: "Invalid C_NUM parameter" });
//   }
//   const sqlQuery = "SELECT * FROM simpleboard where C_NUM = (?)";

//   db.query(sqlQuery, [C_NUM], (err, result) => {
//     if (err) {
//       return res.status(500).send({ error: "Error executing query" });
//     }
//     res.send(result);
//   });
// });
// app.post("/contentedit/insert", (req, res) => {
//   // const param = req.body;
//   const title = req.body.title;
//   const content = req.body.content;
//   let C_P_NUM = parseInt(req.body.C_P_NUM);
//   console.log(C_P_NUM);
//   console.log("C_P_NUM");

//   if (!C_P_NUM) {
//     C_P_NUM = 0;
//   }
//   // const blockquoteCode = req.body.blockquoteCode;
//   console.log(title);
//   console.log(content);
//   console.log(C_P_NUM);
//   // console.log(blockquoteCode);
//   const sql =
//     "INSERT INTO simpleboard (title, content, C_P_NUM) VALUES (?, ?, ?)";
//   db.query(sql, [title, content, C_P_NUM], (err, result) => {
//     if (err) {
//       // 쿼리를 실행하는 도중에 오류가 발생했을 때 처리할 코드
//       res.send({
//         success: false,
//         message: err.message,
//       });
//     } else {
//       // 쿼리 실행이 완료된 후 결과를 확인하는 코드
//       if (result.affectedRows > 0) {
//         // 쿼리가 정상적으로 실행되고 데이터가 추가된 경우
//         res.send({
//           success: true,
//           message: "Data added successfully!",
//         });
//       } else {
//         // 쿼리가 정상적으로 실행되지만 데이터가 추가되지 않은 경우
//         res.send({
//           success: false,
//           message: "Data was not added. Please try again.",
//         });
//       }
//     }
//     // });
//     // res.end();
//   });
// });
// app.post("/contentedit/insert", (req, res) => {
//   // const param = req.body;
//   const title = req.body.title;
//   const content = req.body.content;
//   const C_USER_NUM = req.body.C_USER_NUM;
//   const C_USER_ADDR = req.body.C_USER_ADDR;
//   const C_CUT = req.body.C_CUT;
//   const C_P_NUM = req.body.C_P_NUM;
//   const C_TRANS = req.body.C_TRANS;
//   // const blockquoteCode = req.body.blockquoteCode;
//   console.log(title);
//   console.log(content);
//   console.log(C_USER_NUM);
//   console.log(C_USER_ADDR);
//   console.log(C_CUT);
//   console.log(C_P_NUM);
//   console.log(C_TRANS);
//   // console.log(blockquoteCode);
//   // const sql = "INSERT INTO simpleboard (title, content) VALUES (?, ?)";
//   const sql =
//     "insert into CONTENTS (C_TITLE, C_text, C_USER_NUM, C_USER_ADDR, C_CUT, C_P_NUM, C_TRANS) values(?, ?, ?, ?, ?, ?, ?)";
//   db.query(
//     sql,
//     [title, content, C_USER_NUM, C_USER_ADDR, C_CUT, C_P_NUM, C_TRANS],
//     (err, result) => {
//       if (err) {
//         // 쿼리를 실행하는 도중에 오류가 발생했을 때 처리할 코드
//         res.send({
//           success: false,
//           message: err.message,
//         });
//       } else {
//         // 쿼리 실행이 완료된 후 결과를 확인하는 코드
//         if (result.affectedRows > 0) {
//           // 쿼리가 정상적으로 실행되고 데이터가 추가된 경우
//           res.send({
//             success: true,
//             message: "Data added successfully!",
//           });
//         } else {
//           // 쿼리가 정상적으로 실행되지만 데이터가 추가되지 않은 경우
//           res.send({
//             success: false,
//             message: "Data was not added. Please try again.",
//           });
//         }
//       }
//       // });
//       // res.end();
//     }
//   );
// });
// app.post("/contentedit/insert", (req, res) => {
//   // const param = req.body;
//   const title = req.body.title;
//   const content = req.body.content;
//   const C_USER_NUM = req.body.C_USER_NUM;
//   const C_USER_ADDR = req.body.C_USER_ADDR;
//   const C_CUT = req.body.C_CUT;
//   const C_P_NUM = req.body.C_P_NUM;
//   const C_TRANS = req.body.C_TRANS;
//   // const blockquoteCode = req.body.blockquoteCode;
//   console.log(title);
//   console.log(content);
//   console.log(C_USER_NUM);
//   console.log(C_USER_ADDR);
//   console.log(C_CUT);
//   console.log(C_P_NUM);
//   console.log(C_TRANS);
//   const Co_text = req.body.Co_text;
//   const Co_USER_ADDR = req.body.Co_USER_ADDR;
//   const Co_C_P_NUM = req.body.Co_C_P_NUM;
//   const Co_C_NUM = req.body.Co_C_NUM;
//   console.log(Co_text);
//   console.log(Co_USER_ADDR);
//   console.log(Co_C_P_NUM);
//   console.log(Co_C_NUM);
//   console.log("11111111111");
//   // console.log(blockquoteCode);
//   // const sql = "INSERT INTO simpleboard (title, content) VALUES (?, ?)";
//   const sql =
//     "insert into CONTENTS (C_TITLE, C_text, C_USER_NUM, C_USER_ADDR, C_CUT, C_P_NUM, C_TRANS) values(?, ?, ?, ?, ?, ?, ?)";
//   const sql2 =
//     "insert into code (Co_text, Co_USER_ADDR, Co_C_P_NUM, Co_C_NUM) values(?, ?, ?, ?)";
//   db.query(
//     sql,
//     [title, content, C_USER_NUM, C_USER_ADDR, C_CUT, C_P_NUM, C_TRANS],
//     (err, result) => {
//       if (err) {
//         // 쿼리를 실행하는 도중에 오류가 발생했을 때 처리할 코드
//         res.send({
//           success: false,
//           message: err.message,
//         });
//         console.log("errorrrr");
//       } else {
//         for (let i = 0; Co_C_P_NUM.length; i++) {
//           db.query(
//             sql2,
//             [Co_text[i], Co_USER_ADDR[i], Co_C_P_NUM[i], Co_C_NUM],
//             (err, result) => {
//               if (err) {
//                 // 쿼리를 실행하는 도중에 오류가 발생했을 때 처리할 코드
//                 res.send({
//                   success: false,
//                   message: err.message,
//                 });
//               } else {
//                 // 쿼리 실행이 완료된 후 결과를 확인하는 코드
//                 if (result.affectedRows > 0) {
//                   // 쿼리가 정상적으로 실행되고 데이터가 추가된 경우
//                   res.send({
//                     success: true,
//                     message: "Data added successfully!",
//                   });
//                 }
//                 // else {
//                 //   // 쿼리가 정상적으로 실행되지만 데이터가 추가되지 않은 경우
//                 //   res.send({
//                 //     success: false,
//                 //     message: "Data was not added. Please try again.",
//                 //   });
//                 // }
//               }
//             }
//           );
//           // });
//           // res.end();
//         }
//       }
//     }
//   );
// });
app.post("/contentedit/insert", (req, res) => {
  // const param = req.body;
  const title = req.body.title;
  const content = req.body.content;
  const C_USER_NUM = req.body.C_USER_NUM;
  const C_USER_ADDR = req.body.C_USER_ADDR;
  const C_CUT = req.body.C_CUT;
  const C_P_NUM = req.body.C_P_NUM;
  const C_TRANS = req.body.C_TRANS;
  const C_CA_NUM = req.body.C_CA_NUM;
  // const blockquoteCode = req.body.blockquoteCode;
  console.log(title);
  console.log(content);
  console.log(C_USER_NUM);
  console.log(C_USER_ADDR);
  console.log(C_CUT);
  console.log(C_P_NUM);
  console.log(C_TRANS);
  console.log(C_CA_NUM);
  const Co_text = req.body.Co_text;
  const Co_USER_ADDR = req.body.Co_USER_ADDR;
  const Co_C_P_NUM = req.body.Co_C_P_NUM;
  const Co_C_NUM = req.body.Co_C_NUM;
  console.log(Co_text);
  console.log(Co_USER_ADDR);
  console.log(Co_C_P_NUM);
  console.log(Co_C_NUM);
  console.log("11111111111");
  // console.log(blockquoteCode);
  // const sql = "INSERT INTO simpleboard (title, content) VALUES (?, ?)";
  const sql =
    "insert into CONTENTS (C_TITLE, C_text, C_USER_NUM, C_USER_ADDR, C_CUT, C_P_NUM, C_TRANS, C_CA_NUM) values(?, ?, ?, ?, ?, ?, ?, ?)";
  const sql2 =
    "insert into code (Co_text, Co_USER_ADDR, Co_C_P_NUM, Co_C_NUM) values(?, ?, ?, ?)";
  db.query(
    sql,
    [
      title,
      content,
      C_USER_NUM,
      C_USER_ADDR,
      C_CUT,
      C_P_NUM,
      C_TRANS,
      C_CA_NUM,
    ],
    (err, result) => {
      console.log(result);
      console.log("sql 결과");
      if (err) {
        // 쿼리를 실행하는 도중에 오류가 발생했을 때 처리할 코드
        res.send({
          success: false,
          message: err.message,
        });
        console.log("errorrrr");
      } else {
        for (let i = 0; i < Co_C_P_NUM.length; i++) {
          db.query(
            sql2,
            [Co_text[i], Co_USER_ADDR[i], Co_C_P_NUM[i], Co_C_NUM],
            (err, result) => {
              console.log(result);
              console.log("sql2 결과");
              console.log(Co_C_P_NUM);
              if (err) {
                // 쿼리를 실행하는 도중에 오류가 발생했을 때 처리할 코드
                res.send({
                  success: false,
                  message: err.message,
                });
              }
              // else {
              //   // 쿼리 실행이 완료된 후 결과를 확인하는 코드
              //   if (result.affectedRows > 0) {
              //     // 쿼리가 정상적으로 실행되고 데이터가 추가된 경우
              //     res.send({
              //       success: true,
              //       message: "Data added successfully!",
              //     });
              //   }
              // else {
              //   // 쿼리가 정상적으로 실행되지만 데이터가 추가되지 않은 경우
              //   res.send({
              //     success: false,
              //     message: "Data was not added. Please try again.",
              //   });
              // }
              // }
            }
          );
        }
        // });
      }
    }
  );
  res.end();
});
// app.post("/contentedit/insert", (req, res) => {
//   // const param = req.body;
//   const title = req.body.title;
//   const content = req.body.content;
//   const C_USER_NUM = req.body.C_USER_NUM;
//   const C_USER_ADDR = req.body.C_USER_ADDR;
//   const C_CUT = req.body.C_CUT;
//   const C_P_NUM = req.body.C_P_NUM;
//   const C_TRANS = req.body.C_TRANS;
//   // const blockquoteCode = req.body.blockquoteCode;
//   console.log(title);
//   console.log(content);
//   console.log(C_USER_NUM);
//   console.log(C_USER_ADDR);
//   console.log(C_CUT);
//   console.log(C_P_NUM);
//   console.log(C_TRANS);
//   const Co_text = req.body.Co_text;
//   const Co_USER_ADDR = req.body.Co_USER_ADDR;
//   const Co_C_P_NUM = req.body.Co_C_P_NUM;
//   const Co_C_NUM = req.body.Co_C_NUM;
//   console.log(Co_text);
//   console.log(Co_USER_ADDR);
//   console.log(Co_C_P_NUM);
//   console.log(Co_C_NUM);
//   console.log("11111111111");
//   // console.log(blockquoteCode);
//   // const sql = "INSERT INTO simpleboard (title, content) VALUES (?, ?)";
//   const sql =
//     "insert into CONTENTS (C_TITLE, C_text, C_USER_NUM, C_USER_ADDR, C_CUT, C_P_NUM, C_TRANS) values(?, ?, ?, ?, ?, ?, ?)";
//   const sqls = mysql.format(sql, title, content, C_USER_NUM, C_USER_ADDR, C_CUT, C_P_NUM, C_TRANS);
//   const sql2 =
//     "insert into code (Co_text, Co_USER_ADDR, Co_C_P_NUM, Co_C_NUM) values(?, ?, ?, ?)";
//   const sql2s = mysql.format(sql2, Co_text[i], Co_USER_ADDR[i], Co_C_P_NUM[i], Co_C_NUM)
//   db.query(
//     sql,
//     [title, content, C_USER_NUM, C_USER_ADDR, C_CUT, C_P_NUM, C_TRANS],
//     (err, result) => {
//       if (err) {
//         // 쿼리를 실행하는 도중에 오류가 발생했을 때 처리할 코드
//         res.send({
//           success: false,
//           message: err.message,
//         });
//         console.log("errorrrr");
//       } else {
//         for (let i = 0; Co_C_P_NUM.length; i++) {
//           db.query(
//             sql2,
//             [Co_text[i], Co_USER_ADDR[i], Co_C_P_NUM[i], Co_C_NUM],
//             (err, result) => {
//               if (err) {
//                 // 쿼리를 실행하는 도중에 오류가 발생했을 때 처리할 코드
//                 res.send({
//                   success: false,
//                   message: err.message,
//                 });
//               } else {
//                 // 쿼리 실행이 완료된 후 결과를 확인하는 코드
//                 if (result.affectedRows > 0) {
//                   // 쿼리가 정상적으로 실행되고 데이터가 추가된 경우
//                   res.send({
//                     success: true,
//                     message: "Data added successfully!",
//                   });
//                 }
//                 // else {
//                 //   // 쿼리가 정상적으로 실행되지만 데이터가 추가되지 않은 경우
//                 //   res.send({
//                 //     success: false,
//                 //     message: "Data was not added. Please try again.",
//                 //   });
//                 // }
//               }
//             }
//           );
//           // });
//           // res.end();
//         }
//       }
//     }
//   );
// });
//post app.post("/contentedit/update")
//get app.get("/mypage")
//post aap.post("/mypage/update")
//get app.get("/portfolio/userId")

// app.get("/api/user/id", (req, res) => {
//   const sql = "SELECT userId FROM User";
//   db.query(sql, (err, rows, fields) => {
//     if (err) {
//       console.log(err);
//     } else {
//       console.log(rows);
//       res.send(rows);
//     }
//   });
// });
// app.get("/api/users/user", (req, res) => {
//   const user_id = req.query.user_id;

//   //filter라는 함수는 자바스크립트에서 배열 함수이다. 필터링을 할때 많이 사용된다 필터링한 데이터를 새로운 배열로 반환한다.
//   const user = users.filter((data) => data.id == user_id);

//   res.json({ ok: false, user: user });
// });
// app.post("/adduser", (req, res) => {
//   const sql = `insert into new_table (user_id) values (1515)`;
//   db.query(sql, (err, result) => {
//     res.send(result);
//   });
// });

// app.get("/contentedit", (req, res) => {
//   const sqlQuery = "SELECT * FROM BOARD;";
//   db.query(sqlQuery, (err, result) => {
//     res.send(result);
//   });
// });

// app.post("/users", function (request, response) {
//   // Get the data for the new user from the request body
//   var userData = request.body;

//   // Construct a SQL query to insert the new user
//   var sql = "INSERT INTO users (name, email) VALUES (?, ?)";

//   // Execute the query
//   db.query(sql, [userData.name, userData.email], function (err, result) {
//     if (err) {
//       // If there was an error, send a server error response
//       response.status(500).send("Error inserting user into database: " + err);
//     } else {
//       // Otherwise, send a success response
//       response.send("User successfully added to database");
//     }
//   });
// });

// app.post("/addCustomer", async (req, res) => {
//   console.log(req);
//   // const body = req.body;
//   const { c_name, c_phone, c_birth, c_gender, c_add, c_adddetail } = req.body;
//   db.query(
//     // `insert into customers_table (name, phone, birth, gender, add1, add2) values ('${c_name}', '${c_phone}', '${c_birth}', '${c_gender}', '${c_add}', '${c_adddetail}')`,
//     "insert into new_table (user_id) values (12)",
//     // "insert into customers_table(name, phone, birth, gender, add1, add2) values(?, ?, ?, ?, ?, ?)",
//     [c_name, c_phone, c_birth, c_gender, c_add, c_adddetail],
//     (err, rows, fields) => {
//       res.send("등록되셨습니다.");
//     }
//   );
// });

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
});

//항상 제일 밑

app.use(express.static(path.join(__dirname, "./build")));
// res.send(express.static(path.join(__dirname, './build/index.html')));
app.get("/", function (요청, 응답) {
  응답.sendFile(path.join(__dirname, "./build/index.html"));
});

// app.use("/", express.static(path.join(__dirname, "public")));
// app.use("/devwiki", express.static(path.join(__dirname, "build/index.html")));

// app.get("/", function (요청, 응답) {
//   응답.sendFile(path.join(__dirname, "public/main.html"));
// });
app.get("/devwiki", function (요청, 응답) {
  응답.sendFile(path.join(__dirname, "./build/index.html"));
});
// // url 입력하면 서버로 가장 하단
app.get("*", function (요청, 응답) {
  응답.sendFile(path.join(__dirname, "./build/index.html"));
});
// app.get("/api/meal", (req, res) => {
//   sql = `select meal from school`;

//   db.query(sql, (err, data) => {
//     if (!err) res.send({ products: data });
//     else res.send(err);
//   });
// });

// sql 연동
// const db = mysql.createConnection({
//   host: "localhost",
//   user: "jjw3310",
//   password: "Dev2022@",
//   database: "devwiki",
// });

// const dbconfig = require("./src/config/dbconfig.js");
// const db = mysql.createConnection(dbconfig);
// // 잘 연동 되었는지 확인
// db.connect(function (err) {
//   if (err) throw err;
//   console.log("DB is Connected!");
// });
