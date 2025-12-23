.class public final synthetic Llyiahf/vczjk/nk5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/zl8;

.field public final synthetic OooOOO0:Z

.field public final synthetic OooOOOO:Ljava/lang/String;

.field public final synthetic OooOOOo:Ljava/lang/String;

.field public final synthetic OooOOo:Llyiahf/vczjk/le3;

.field public final synthetic OooOOo0:Ljava/lang/String;

.field public final synthetic OooOOoo:Llyiahf/vczjk/xr1;


# direct methods
.method public synthetic constructor <init>(ZLlyiahf/vczjk/zl8;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/le3;Llyiahf/vczjk/xr1;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Llyiahf/vczjk/nk5;->OooOOO0:Z

    iput-object p2, p0, Llyiahf/vczjk/nk5;->OooOOO:Llyiahf/vczjk/zl8;

    iput-object p3, p0, Llyiahf/vczjk/nk5;->OooOOOO:Ljava/lang/String;

    iput-object p4, p0, Llyiahf/vczjk/nk5;->OooOOOo:Ljava/lang/String;

    iput-object p5, p0, Llyiahf/vczjk/nk5;->OooOOo0:Ljava/lang/String;

    iput-object p6, p0, Llyiahf/vczjk/nk5;->OooOOo:Llyiahf/vczjk/le3;

    iput-object p7, p0, Llyiahf/vczjk/nk5;->OooOOoo:Llyiahf/vczjk/xr1;

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Llyiahf/vczjk/af8;

    iget-boolean v0, p0, Llyiahf/vczjk/nk5;->OooOOO0:Z

    if-eqz v0, :cond_1

    new-instance v0, Llyiahf/vczjk/ok5;

    iget-object v1, p0, Llyiahf/vczjk/nk5;->OooOOo:Llyiahf/vczjk/le3;

    const/4 v2, 0x0

    invoke-direct {v0, v2, v1}, Llyiahf/vczjk/ok5;-><init>(ILlyiahf/vczjk/le3;)V

    sget-object v1, Llyiahf/vczjk/ye8;->OooO00o:[Llyiahf/vczjk/th4;

    sget-object v1, Llyiahf/vczjk/ie8;->OooOo0:Llyiahf/vczjk/ze8;

    new-instance v2, Llyiahf/vczjk/o0O00O;

    iget-object v3, p0, Llyiahf/vczjk/nk5;->OooOOOO:Ljava/lang/String;

    invoke-direct {v2, v3, v0}, Llyiahf/vczjk/o0O00O;-><init>(Ljava/lang/String;Llyiahf/vczjk/cf3;)V

    check-cast p1, Llyiahf/vczjk/je8;

    invoke-virtual {p1, v1, v2}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    iget-object v0, p0, Llyiahf/vczjk/nk5;->OooOOO:Llyiahf/vczjk/zl8;

    invoke-virtual {v0}, Llyiahf/vczjk/zl8;->OooO0OO()Llyiahf/vczjk/am8;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/am8;->OooOOOO:Llyiahf/vczjk/am8;

    iget-object v3, p0, Llyiahf/vczjk/nk5;->OooOOoo:Llyiahf/vczjk/xr1;

    if-ne v1, v2, :cond_0

    new-instance v1, Llyiahf/vczjk/x5;

    const/16 v2, 0xb

    invoke-direct {v1, v0, v3, v2, v0}, Llyiahf/vczjk/x5;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    sget-object v0, Llyiahf/vczjk/ie8;->OooOOoo:Llyiahf/vczjk/ze8;

    new-instance v2, Llyiahf/vczjk/o0O00O;

    iget-object v3, p0, Llyiahf/vczjk/nk5;->OooOOOo:Ljava/lang/String;

    invoke-direct {v2, v3, v1}, Llyiahf/vczjk/o0O00O;-><init>(Ljava/lang/String;Llyiahf/vczjk/cf3;)V

    invoke-virtual {p1, v0, v2}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    iget-object v1, v0, Llyiahf/vczjk/zl8;->OooO0o0:Llyiahf/vczjk/c9;

    invoke-virtual {v1}, Llyiahf/vczjk/c9;->OooO0Oo()Llyiahf/vczjk/kb5;

    move-result-object v1

    iget-object v1, v1, Llyiahf/vczjk/kb5;->OooO00o:Ljava/lang/Object;

    invoke-interface {v1, v2}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    new-instance v1, Llyiahf/vczjk/bg0;

    const/4 v2, 0x4

    invoke-direct {v1, v0, v3, v2}, Llyiahf/vczjk/bg0;-><init>(Llyiahf/vczjk/zl8;Llyiahf/vczjk/xr1;I)V

    sget-object v0, Llyiahf/vczjk/ie8;->OooOo00:Llyiahf/vczjk/ze8;

    new-instance v2, Llyiahf/vczjk/o0O00O;

    iget-object v3, p0, Llyiahf/vczjk/nk5;->OooOOo0:Ljava/lang/String;

    invoke-direct {v2, v3, v1}, Llyiahf/vczjk/o0O00O;-><init>(Ljava/lang/String;Llyiahf/vczjk/cf3;)V

    invoke-virtual {p1, v0, v2}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    :cond_1
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
