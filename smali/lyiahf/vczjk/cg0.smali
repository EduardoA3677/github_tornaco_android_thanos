.class public final synthetic Llyiahf/vczjk/cg0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Z

.field public final synthetic OooOOO0:Llyiahf/vczjk/zl8;

.field public final synthetic OooOOOO:Ljava/lang/String;

.field public final synthetic OooOOOo:Ljava/lang/String;

.field public final synthetic OooOOo:Llyiahf/vczjk/xr1;

.field public final synthetic OooOOo0:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/zl8;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/xr1;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/cg0;->OooOOO0:Llyiahf/vczjk/zl8;

    iput-boolean p2, p0, Llyiahf/vczjk/cg0;->OooOOO:Z

    iput-object p3, p0, Llyiahf/vczjk/cg0;->OooOOOO:Ljava/lang/String;

    iput-object p4, p0, Llyiahf/vczjk/cg0;->OooOOOo:Ljava/lang/String;

    iput-object p5, p0, Llyiahf/vczjk/cg0;->OooOOo0:Ljava/lang/String;

    iput-object p6, p0, Llyiahf/vczjk/cg0;->OooOOo:Llyiahf/vczjk/xr1;

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    const/4 v0, 0x1

    check-cast p1, Llyiahf/vczjk/af8;

    iget-object v1, p0, Llyiahf/vczjk/cg0;->OooOOO0:Llyiahf/vczjk/zl8;

    iget-object v2, v1, Llyiahf/vczjk/zl8;->OooO0o0:Llyiahf/vczjk/c9;

    invoke-virtual {v2}, Llyiahf/vczjk/c9;->OooO0Oo()Llyiahf/vczjk/kb5;

    move-result-object v2

    iget-object v2, v2, Llyiahf/vczjk/kb5;->OooO00o:Ljava/lang/Object;

    invoke-interface {v2}, Ljava/util/Map;->size()I

    move-result v2

    if-le v2, v0, :cond_2

    iget-boolean v2, p0, Llyiahf/vczjk/cg0;->OooOOO:Z

    if-eqz v2, :cond_2

    invoke-virtual {v1}, Llyiahf/vczjk/zl8;->OooO0OO()Llyiahf/vczjk/am8;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/am8;->OooOOOO:Llyiahf/vczjk/am8;

    iget-object v4, v1, Llyiahf/vczjk/zl8;->OooO0o0:Llyiahf/vczjk/c9;

    iget-object v5, p0, Llyiahf/vczjk/cg0;->OooOOo:Llyiahf/vczjk/xr1;

    if-ne v2, v3, :cond_0

    iget-object v0, v4, Llyiahf/vczjk/c9;->OooO0Oo:Llyiahf/vczjk/oe3;

    sget-object v2, Llyiahf/vczjk/am8;->OooOOO:Llyiahf/vczjk/am8;

    invoke-interface {v0, v2}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-eqz v0, :cond_1

    new-instance v0, Llyiahf/vczjk/bg0;

    const/4 v2, 0x0

    invoke-direct {v0, v5, v1, v2}, Llyiahf/vczjk/bg0;-><init>(Llyiahf/vczjk/xr1;Llyiahf/vczjk/zl8;I)V

    sget-object v2, Llyiahf/vczjk/ye8;->OooO00o:[Llyiahf/vczjk/th4;

    sget-object v2, Llyiahf/vczjk/ie8;->OooOOoo:Llyiahf/vczjk/ze8;

    new-instance v3, Llyiahf/vczjk/o0O00O;

    iget-object v4, p0, Llyiahf/vczjk/cg0;->OooOOOO:Ljava/lang/String;

    invoke-direct {v3, v4, v0}, Llyiahf/vczjk/o0O00O;-><init>(Ljava/lang/String;Llyiahf/vczjk/cf3;)V

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/je8;

    invoke-virtual {v0, v2, v3}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    iget-object v2, v4, Llyiahf/vczjk/c9;->OooO0Oo:Llyiahf/vczjk/oe3;

    invoke-interface {v2, v3}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Boolean;

    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v2

    if-eqz v2, :cond_1

    new-instance v2, Llyiahf/vczjk/bg0;

    invoke-direct {v2, v5, v1, v0}, Llyiahf/vczjk/bg0;-><init>(Llyiahf/vczjk/xr1;Llyiahf/vczjk/zl8;I)V

    sget-object v0, Llyiahf/vczjk/ye8;->OooO00o:[Llyiahf/vczjk/th4;

    sget-object v0, Llyiahf/vczjk/ie8;->OooOo00:Llyiahf/vczjk/ze8;

    new-instance v3, Llyiahf/vczjk/o0O00O;

    iget-object v4, p0, Llyiahf/vczjk/cg0;->OooOOOo:Ljava/lang/String;

    invoke-direct {v3, v4, v2}, Llyiahf/vczjk/o0O00O;-><init>(Ljava/lang/String;Llyiahf/vczjk/cf3;)V

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/je8;

    invoke-virtual {v2, v0, v3}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    :cond_1
    :goto_0
    iget-boolean v0, v1, Llyiahf/vczjk/zl8;->OooO0OO:Z

    if-nez v0, :cond_2

    new-instance v0, Llyiahf/vczjk/bg0;

    const/4 v2, 0x2

    invoke-direct {v0, v5, v1, v2}, Llyiahf/vczjk/bg0;-><init>(Llyiahf/vczjk/xr1;Llyiahf/vczjk/zl8;I)V

    sget-object v1, Llyiahf/vczjk/ye8;->OooO00o:[Llyiahf/vczjk/th4;

    sget-object v1, Llyiahf/vczjk/ie8;->OooOo0:Llyiahf/vczjk/ze8;

    new-instance v2, Llyiahf/vczjk/o0O00O;

    iget-object v3, p0, Llyiahf/vczjk/cg0;->OooOOo0:Ljava/lang/String;

    invoke-direct {v2, v3, v0}, Llyiahf/vczjk/o0O00O;-><init>(Ljava/lang/String;Llyiahf/vczjk/cf3;)V

    check-cast p1, Llyiahf/vczjk/je8;

    invoke-virtual {p1, v1, v2}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    :cond_2
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
