.class public Llyiahf/vczjk/ph4;
.super Llyiahf/vczjk/ai4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/mh4;


# instance fields
.field public final OooOo0O:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yf4;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;)V
    .locals 1

    const-string v0, "container"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "name"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "signature"

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0, p1, p2, p3, p4}, Llyiahf/vczjk/ai4;-><init>(Llyiahf/vczjk/yf4;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/ww4;->OooOOO0:Llyiahf/vczjk/ww4;

    new-instance p2, Llyiahf/vczjk/nh4;

    const/4 p3, 0x0

    invoke-direct {p2, p0, p3}, Llyiahf/vczjk/nh4;-><init>(Llyiahf/vczjk/ph4;I)V

    invoke-static {p1, p2}, Llyiahf/vczjk/jp8;->Oooo00o(Llyiahf/vczjk/ww4;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kp4;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/ph4;->OooOo0O:Ljava/lang/Object;

    new-instance p2, Llyiahf/vczjk/nh4;

    const/4 p3, 0x1

    invoke-direct {p2, p0, p3}, Llyiahf/vczjk/nh4;-><init>(Llyiahf/vczjk/ph4;I)V

    invoke-static {p1, p2}, Llyiahf/vczjk/jp8;->Oooo00o(Llyiahf/vczjk/ww4;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kp4;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/yf4;Llyiahf/vczjk/ua7;)V
    .locals 1

    const-string v0, "container"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "descriptor"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/ai4;-><init>(Llyiahf/vczjk/yf4;Llyiahf/vczjk/ua7;)V

    sget-object p1, Llyiahf/vczjk/ww4;->OooOOO0:Llyiahf/vczjk/ww4;

    new-instance p2, Llyiahf/vczjk/nh4;

    const/4 v0, 0x0

    invoke-direct {p2, p0, v0}, Llyiahf/vczjk/nh4;-><init>(Llyiahf/vczjk/ph4;I)V

    invoke-static {p1, p2}, Llyiahf/vczjk/jp8;->Oooo00o(Llyiahf/vczjk/ww4;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kp4;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/ph4;->OooOo0O:Ljava/lang/Object;

    new-instance p2, Llyiahf/vczjk/nh4;

    const/4 v0, 0x1

    invoke-direct {p2, p0, v0}, Llyiahf/vczjk/nh4;-><init>(Llyiahf/vczjk/ph4;I)V

    invoke-static {p1, p2}, Llyiahf/vczjk/jp8;->Oooo00o(Llyiahf/vczjk/ww4;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kp4;

    return-void
.end method


# virtual methods
.method public final OooO0O0()Llyiahf/vczjk/fh4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ph4;->OooOo0O:Ljava/lang/Object;

    invoke-interface {v0}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/oh4;

    return-object v0
.end method

.method public final OooO0O0()Llyiahf/vczjk/lh4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ph4;->OooOo0O:Ljava/lang/Object;

    invoke-interface {v0}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/oh4;

    return-object v0
.end method

.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/ph4;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final OooOo0()Llyiahf/vczjk/xh4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ph4;->OooOo0O:Ljava/lang/Object;

    invoke-interface {v0}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/oh4;

    return-object v0
.end method

.method public final get(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ph4;->OooOo0O:Ljava/lang/Object;

    invoke-interface {v0}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/oh4;

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ff4;->OooO0oo([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
