.class public final Llyiahf/vczjk/di0;
.super Llyiahf/vczjk/jl5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oh0;
.implements Llyiahf/vczjk/vn4;


# instance fields
.field public OooOoOO:Llyiahf/vczjk/um1;

.field public OooOoo0:Z


# direct methods
.method public static final o00000OO(Llyiahf/vczjk/di0;Llyiahf/vczjk/xn4;Llyiahf/vczjk/le3;)Llyiahf/vczjk/wj7;
    .locals 2

    iget-boolean v0, p0, Llyiahf/vczjk/jl5;->OooOoO:Z

    const/4 v1, 0x0

    if-nez v0, :cond_0

    goto :goto_1

    :cond_0
    iget-boolean v0, p0, Llyiahf/vczjk/di0;->OooOoo0:Z

    if-nez v0, :cond_1

    goto :goto_1

    :cond_1
    invoke-static {p0}, Llyiahf/vczjk/yi4;->oo000o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/v16;

    move-result-object p0

    invoke-interface {p1}, Llyiahf/vczjk/xn4;->OooOO0o()Z

    move-result v0

    if-eqz v0, :cond_2

    goto :goto_0

    :cond_2
    move-object p1, v1

    :goto_0
    if-nez p1, :cond_3

    goto :goto_1

    :cond_3
    invoke-interface {p2}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/wj7;

    if-nez p2, :cond_4

    :goto_1
    return-object v1

    :cond_4
    const/4 v0, 0x0

    invoke-virtual {p0, p1, v0}, Llyiahf/vczjk/v16;->OooOOO0(Llyiahf/vczjk/xn4;Z)Llyiahf/vczjk/wj7;

    move-result-object p0

    invoke-virtual {p0}, Llyiahf/vczjk/wj7;->OooO0Oo()J

    move-result-wide p0

    invoke-virtual {p2, p0, p1}, Llyiahf/vczjk/wj7;->OooO(J)Llyiahf/vczjk/wj7;

    move-result-object p0

    return-object p0
.end method


# virtual methods
.method public final OooOo0(Llyiahf/vczjk/xn4;)V
    .locals 0

    const/4 p1, 0x1

    iput-boolean p1, p0, Llyiahf/vczjk/di0;->OooOoo0:Z

    return-void
.end method

.method public final OooooOO(Llyiahf/vczjk/v16;Llyiahf/vczjk/ph0;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 6

    new-instance v4, Llyiahf/vczjk/ci0;

    invoke-direct {v4, p0, p1, p2}, Llyiahf/vczjk/ci0;-><init>(Llyiahf/vczjk/di0;Llyiahf/vczjk/v16;Llyiahf/vczjk/ph0;)V

    new-instance v0, Llyiahf/vczjk/bi0;

    const/4 v5, 0x0

    move-object v1, p0

    move-object v2, p1

    move-object v3, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/bi0;-><init>(Llyiahf/vczjk/di0;Llyiahf/vczjk/xn4;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/yo1;)V

    invoke-static {v0, p3}, Llyiahf/vczjk/v34;->Oooo00O(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_0

    return-object p1

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

.method public final o0Oo0oo()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method
