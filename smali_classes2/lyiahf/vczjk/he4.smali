.class public final Llyiahf/vczjk/he4;
.super Llyiahf/vczjk/t51;
.source "SourceFile"


# instance fields
.field public final OooOOO:Llyiahf/vczjk/xc7;

.field public final OooOOO0:Llyiahf/vczjk/sa7;

.field public final OooOOOO:Llyiahf/vczjk/oe4;

.field public final OooOOOo:Llyiahf/vczjk/rt5;

.field public final OooOOo:Ljava/lang/String;

.field public final OooOOo0:Llyiahf/vczjk/h87;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/sa7;Llyiahf/vczjk/xc7;Llyiahf/vczjk/oe4;Llyiahf/vczjk/rt5;Llyiahf/vczjk/h87;)V
    .locals 2

    const-string v0, "proto"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "nameResolver"

    invoke-static {p4, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "typeTable"

    invoke-static {p5, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/he4;->OooOOO0:Llyiahf/vczjk/sa7;

    iput-object p2, p0, Llyiahf/vczjk/he4;->OooOOO:Llyiahf/vczjk/xc7;

    iput-object p3, p0, Llyiahf/vczjk/he4;->OooOOOO:Llyiahf/vczjk/oe4;

    iput-object p4, p0, Llyiahf/vczjk/he4;->OooOOOo:Llyiahf/vczjk/rt5;

    iput-object p5, p0, Llyiahf/vczjk/he4;->OooOOo0:Llyiahf/vczjk/h87;

    invoke-virtual {p3}, Llyiahf/vczjk/oe4;->OooOOo()Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-virtual {p3}, Llyiahf/vczjk/oe4;->OooOOO0()Llyiahf/vczjk/me4;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/me4;->OooO()I

    move-result p1

    invoke-interface {p4, p1}, Llyiahf/vczjk/rt5;->Oooo(I)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p3}, Llyiahf/vczjk/oe4;->OooOOO0()Llyiahf/vczjk/me4;

    move-result-object p2

    invoke-virtual {p2}, Llyiahf/vczjk/me4;->OooO0oo()I

    move-result p2

    invoke-interface {p4, p2}, Llyiahf/vczjk/rt5;->Oooo(I)Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p1, p2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    goto/16 :goto_2

    :cond_0
    const/4 p3, 0x1

    invoke-static {p2, p4, p5, p3}, Llyiahf/vczjk/ve4;->OooO0O0(Llyiahf/vczjk/xc7;Llyiahf/vczjk/rt5;Llyiahf/vczjk/h87;Z)Llyiahf/vczjk/zd4;

    move-result-object p2

    if-eqz p2, :cond_4

    new-instance p3, Ljava/lang/StringBuilder;

    invoke-direct {p3}, Ljava/lang/StringBuilder;-><init>()V

    iget-object p5, p2, Llyiahf/vczjk/zd4;->OooO:Ljava/lang/String;

    invoke-static {p5}, Llyiahf/vczjk/bd4;->OooO00o(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p5

    invoke-virtual {p3, p5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-interface {p1}, Llyiahf/vczjk/v02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object p5

    const-string v0, "getContainingDeclaration(...)"

    invoke-static {p5, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p1}, Llyiahf/vczjk/yf5;->OooO0Oo()Llyiahf/vczjk/q72;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/r72;->OooO0Oo:Llyiahf/vczjk/q72;

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    const-string v1, "$"

    if-eqz v0, :cond_2

    instance-of v0, p5, Llyiahf/vczjk/h82;

    if-eqz v0, :cond_2

    check-cast p5, Llyiahf/vczjk/h82;

    sget-object p1, Llyiahf/vczjk/ue4;->OooO:Llyiahf/vczjk/ug3;

    const-string v0, "classModuleName"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p5, p5, Llyiahf/vczjk/h82;->OooOOo0:Llyiahf/vczjk/zb7;

    invoke-static {p5, p1}, Llyiahf/vczjk/tn6;->OooOOO(Llyiahf/vczjk/sg3;Llyiahf/vczjk/ug3;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Integer;

    if-eqz p1, :cond_1

    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    move-result p1

    invoke-interface {p4, p1}, Llyiahf/vczjk/rt5;->Oooo(I)Ljava/lang/String;

    move-result-object p1

    goto :goto_0

    :cond_1
    const-string p1, "main"

    :goto_0
    sget-object p4, Llyiahf/vczjk/xt5;->OooO00o:Llyiahf/vczjk/on7;

    const-string p5, "_"

    invoke-virtual {p4, p1, p5}, Llyiahf/vczjk/on7;->OooO0oO(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {v1, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    goto :goto_1

    :cond_2
    invoke-interface {p1}, Llyiahf/vczjk/yf5;->OooO0Oo()Llyiahf/vczjk/q72;

    move-result-object p4

    sget-object v0, Llyiahf/vczjk/r72;->OooO00o:Llyiahf/vczjk/q72;

    invoke-static {p4, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p4

    if-eqz p4, :cond_3

    instance-of p4, p5, Llyiahf/vczjk/hh6;

    if-eqz p4, :cond_3

    check-cast p1, Llyiahf/vczjk/t82;

    iget-object p1, p1, Llyiahf/vczjk/t82;->OoooO:Llyiahf/vczjk/ce4;

    if-eqz p1, :cond_3

    iget-object p4, p1, Llyiahf/vczjk/ce4;->OooOOO:Llyiahf/vczjk/rd4;

    if-eqz p4, :cond_3

    new-instance p4, Ljava/lang/StringBuilder;

    invoke-direct {p4, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object p1, p1, Llyiahf/vczjk/ce4;->OooOOO0:Llyiahf/vczjk/rd4;

    invoke-virtual {p1}, Llyiahf/vczjk/rd4;->OooO0Oo()Ljava/lang/String;

    move-result-object p1

    const-string p5, "getInternalName(...)"

    invoke-static {p1, p5}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const/16 p5, 0x2f

    invoke-static {p5, p1, p1}, Llyiahf/vczjk/z69;->OoooooO(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p4, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    goto :goto_1

    :cond_3
    const-string p1, ""

    :goto_1
    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p1, "()"

    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object p1, p2, Llyiahf/vczjk/zd4;->OooOO0:Ljava/lang/String;

    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    :goto_2
    iput-object p1, p0, Llyiahf/vczjk/he4;->OooOOo:Ljava/lang/String;

    return-void

    :cond_4
    new-instance p2, Llyiahf/vczjk/es1;

    new-instance p3, Ljava/lang/StringBuilder;

    const-string p4, "No field signature for property: "

    invoke-direct {p3, p4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p2, p1}, Llyiahf/vczjk/es1;-><init>(Ljava/lang/String;)V

    throw p2
.end method


# virtual methods
.method public final OooOOO()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/he4;->OooOOo:Ljava/lang/String;

    return-object v0
.end method
