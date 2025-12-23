.class public final synthetic Llyiahf/vczjk/b74;
.super Llyiahf/vczjk/wf3;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# static fields
.field public static final OooOOO:Llyiahf/vczjk/b74;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    new-instance v0, Llyiahf/vczjk/b74;

    const-string v4, "getDefaultReportLevelForAnnotation(Lorg/jetbrains/kotlin/name/FqName;)Lorg/jetbrains/kotlin/load/java/ReportLevel;"

    const/4 v5, 0x1

    const/4 v1, 0x1

    const-class v2, Llyiahf/vczjk/p64;

    const-string v3, "getDefaultReportLevelForAnnotation"

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/wf3;-><init>(ILjava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    sput-object v0, Llyiahf/vczjk/b74;->OooOOO:Llyiahf/vczjk/b74;

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    check-cast p1, Llyiahf/vczjk/hc3;

    const-string v0, "p0"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/p64;->OooO00o:Llyiahf/vczjk/hc3;

    sget-object v0, Llyiahf/vczjk/w46;->OooO0oo:Llyiahf/vczjk/v46;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v0, Llyiahf/vczjk/v46;->OooO0O0:Llyiahf/vczjk/era;

    new-instance v1, Llyiahf/vczjk/bl4;

    const/16 v2, 0x14

    const/4 v3, 0x1

    const/4 v4, 0x7

    invoke-direct {v1, v3, v4, v2}, Llyiahf/vczjk/bl4;-><init>(III)V

    const-string v2, "configuredReportLevels"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, v0, Llyiahf/vczjk/era;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/r60;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/r60;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/yq7;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    sget-object v0, Llyiahf/vczjk/p64;->OooO0OO:Llyiahf/vczjk/era;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v0, v0, Llyiahf/vczjk/era;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/r60;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/r60;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/q64;

    if-nez p1, :cond_1

    sget-object p1, Llyiahf/vczjk/yq7;->OooOOO0:Llyiahf/vczjk/yq7;

    return-object p1

    :cond_1
    iget-object v0, p1, Llyiahf/vczjk/q64;->OooO0O0:Llyiahf/vczjk/bl4;

    if-eqz v0, :cond_2

    iget v0, v0, Llyiahf/vczjk/bl4;->OooOOOo:I

    iget v1, v1, Llyiahf/vczjk/bl4;->OooOOOo:I

    sub-int/2addr v0, v1

    if-gtz v0, :cond_2

    iget-object p1, p1, Llyiahf/vczjk/q64;->OooO0OO:Llyiahf/vczjk/yq7;

    return-object p1

    :cond_2
    iget-object p1, p1, Llyiahf/vczjk/q64;->OooO00o:Llyiahf/vczjk/yq7;

    return-object p1
.end method
