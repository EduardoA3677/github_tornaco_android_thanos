.class public final Llyiahf/vczjk/lr4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ko;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/b64;

.field public final OooOOO0:Llyiahf/vczjk/ld9;

.field public final OooOOOO:Z

.field public final OooOOOo:Llyiahf/vczjk/r60;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ld9;Llyiahf/vczjk/b64;Z)V
    .locals 1

    const-string v0, "c"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "annotationOwner"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/lr4;->OooOOO0:Llyiahf/vczjk/ld9;

    iput-object p2, p0, Llyiahf/vczjk/lr4;->OooOOO:Llyiahf/vczjk/b64;

    iput-boolean p3, p0, Llyiahf/vczjk/lr4;->OooOOOO:Z

    iget-object p1, p1, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/s64;

    iget-object p1, p1, Llyiahf/vczjk/s64;->OooO00o:Llyiahf/vczjk/q45;

    new-instance p2, Llyiahf/vczjk/oo000o;

    const/16 p3, 0xe

    invoke-direct {p2, p0, p3}, Llyiahf/vczjk/oo000o;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {p1, p2}, Llyiahf/vczjk/q45;->OooO0OO(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/r60;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/lr4;->OooOOOo:Llyiahf/vczjk/r60;

    return-void
.end method


# virtual methods
.method public final OooO0o0(Llyiahf/vczjk/hc3;)Z
    .locals 0

    invoke-static {p0, p1}, Llyiahf/vczjk/mc4;->Oooo0oo(Llyiahf/vczjk/ko;Llyiahf/vczjk/hc3;)Z

    move-result p1

    return p1
.end method

.method public final OooO0oO(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/un;
    .locals 3

    const-string v0, "fqName"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/lr4;->OooOOO:Llyiahf/vczjk/b64;

    invoke-interface {v0, p1}, Llyiahf/vczjk/b64;->OooO00o(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/sl7;

    move-result-object v1

    if-eqz v1, :cond_1

    iget-object v2, p0, Llyiahf/vczjk/lr4;->OooOOOo:Llyiahf/vczjk/r60;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/r60;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/un;

    if-nez v1, :cond_0

    goto :goto_0

    :cond_0
    return-object v1

    :cond_1
    :goto_0
    sget-object v1, Llyiahf/vczjk/a64;->OooO00o:Llyiahf/vczjk/qt5;

    iget-object v1, p0, Llyiahf/vczjk/lr4;->OooOOO0:Llyiahf/vczjk/ld9;

    invoke-static {p1, v0, v1}, Llyiahf/vczjk/a64;->OooO00o(Llyiahf/vczjk/hc3;Llyiahf/vczjk/b64;Llyiahf/vczjk/ld9;)Llyiahf/vczjk/f07;

    move-result-object p1

    return-object p1
.end method

.method public final isEmpty()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/lr4;->OooOOO:Llyiahf/vczjk/b64;

    invoke-interface {v0}, Llyiahf/vczjk/b64;->OooOOo0()Ljava/util/Collection;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final iterator()Ljava/util/Iterator;
    .locals 5

    const/4 v0, 0x0

    iget-object v1, p0, Llyiahf/vczjk/lr4;->OooOOO:Llyiahf/vczjk/b64;

    invoke-interface {v1}, Llyiahf/vczjk/b64;->OooOOo0()Ljava/util/Collection;

    move-result-object v2

    check-cast v2, Ljava/lang/Iterable;

    invoke-static {v2}, Llyiahf/vczjk/d21;->Oooooo(Ljava/lang/Iterable;)Llyiahf/vczjk/vy;

    move-result-object v2

    iget-object v3, p0, Llyiahf/vczjk/lr4;->OooOOOo:Llyiahf/vczjk/r60;

    invoke-static {v2, v3}, Llyiahf/vczjk/ag8;->Oooo0oo(Llyiahf/vczjk/wf8;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/jy9;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/a64;->OooO00o:Llyiahf/vczjk/qt5;

    sget-object v3, Llyiahf/vczjk/w09;->OooOOO0:Llyiahf/vczjk/hc3;

    iget-object v4, p0, Llyiahf/vczjk/lr4;->OooOOO0:Llyiahf/vczjk/ld9;

    invoke-static {v3, v1, v4}, Llyiahf/vczjk/a64;->OooO00o(Llyiahf/vczjk/hc3;Llyiahf/vczjk/b64;Llyiahf/vczjk/ld9;)Llyiahf/vczjk/f07;

    move-result-object v1

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/sy;->Oooooo([Ljava/lang/Object;)Llyiahf/vczjk/wf8;

    move-result-object v1

    const/4 v3, 0x2

    new-array v3, v3, [Llyiahf/vczjk/wf8;

    aput-object v2, v3, v0

    const/4 v2, 0x1

    aput-object v1, v3, v2

    invoke-static {v3}, Llyiahf/vczjk/sy;->Oooooo([Ljava/lang/Object;)Llyiahf/vczjk/wf8;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/ag8;->Oooo0O0(Llyiahf/vczjk/wf8;)Llyiahf/vczjk/oz2;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/r07;

    const/16 v3, 0x17

    invoke-direct {v2, v3}, Llyiahf/vczjk/r07;-><init>(I)V

    new-instance v3, Llyiahf/vczjk/e13;

    invoke-direct {v3, v1, v0, v2}, Llyiahf/vczjk/e13;-><init>(Llyiahf/vczjk/wf8;ZLlyiahf/vczjk/oe3;)V

    new-instance v0, Llyiahf/vczjk/d13;

    invoke-direct {v0, v3}, Llyiahf/vczjk/d13;-><init>(Llyiahf/vczjk/e13;)V

    return-object v0
.end method
