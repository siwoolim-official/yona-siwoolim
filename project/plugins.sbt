logLevel := Level.Warn

resolvers := Seq(
  "Typesafe Repository HTTPS" at "https://repo.typesafe.com/typesafe/releases/",
  "Typesafe Ivy HTTPS" at "https://repo.typesafe.com/typesafe/ivy-releases/",
  Resolver.sonatypeRepo("releases"),
  Resolver.typesafeRepo("releases"),
  Resolver.url("Typesafe Ivy releases", url("https://repo.typesafe.com/typesafe/ivy-releases"))(Resolver.ivyStylePatterns)
)

addSbtPlugin("com.typesafe.play" % "sbt-plugin" % "2.3.10")

addSbtPlugin("com.typesafe.sbt" % "sbt-less" % "1.0.4")

addSbtPlugin("com.typesafe.sbt" % "sbt-twirl" % "1.0.3")

addSbtPlugin("de.johoop" % "findbugs4sbt" % "1.4.0")

addSbtPlugin("com.eed3si9n" % "sbt-buildinfo" % "0.3.2")

addSbtPlugin("net.virtual-void" % "sbt-dependency-graph" % "0.7.4")