.class public final Llyiahf/vczjk/ak0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/dy0;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/q45;

.field public final OooO0O0:Llyiahf/vczjk/dm5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/dm5;)V
    .locals 1

    const-string v0, "module"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ak0;->OooO00o:Llyiahf/vczjk/q45;

    iput-object p2, p0, Llyiahf/vczjk/ak0;->OooO0O0:Llyiahf/vczjk/dm5;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/hc3;Llyiahf/vczjk/qt5;)Z
    .locals 2

    const-string v0, "packageFqName"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "name"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p2}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object p2

    const-string v0, "asString(...)"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "Function"

    const/4 v1, 0x0

    invoke-static {p2, v0, v1}, Llyiahf/vczjk/g79;->Oooo00o(Ljava/lang/String;Ljava/lang/String;Z)Z

    move-result v0

    if-nez v0, :cond_0

    const-string v0, "KFunction"

    invoke-static {p2, v0, v1}, Llyiahf/vczjk/g79;->Oooo00o(Ljava/lang/String;Ljava/lang/String;Z)Z

    move-result v0

    if-nez v0, :cond_0

    const-string v0, "SuspendFunction"

    invoke-static {p2, v0, v1}, Llyiahf/vczjk/g79;->Oooo00o(Ljava/lang/String;Ljava/lang/String;Z)Z

    move-result v0

    if-nez v0, :cond_0

    const-string v0, "KSuspendFunction"

    invoke-static {p2, v0, v1}, Llyiahf/vczjk/g79;->Oooo00o(Ljava/lang/String;Ljava/lang/String;Z)Z

    move-result v0

    if-eqz v0, :cond_1

    :cond_0
    sget-object v0, Llyiahf/vczjk/dg3;->OooO0OO:Llyiahf/vczjk/dg3;

    invoke-virtual {v0, p2, p1}, Llyiahf/vczjk/dg3;->OooO00o(Ljava/lang/String;Llyiahf/vczjk/hc3;)Llyiahf/vczjk/cg3;

    move-result-object p1

    if-eqz p1, :cond_1

    const/4 p1, 0x1

    return p1

    :cond_1
    return v1
.end method

.method public final OooO0O0(Llyiahf/vczjk/hy0;)Llyiahf/vczjk/by0;
    .locals 4

    const-string v0, "classId"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-boolean v0, p1, Llyiahf/vczjk/hy0;->OooO0OO:Z

    if-nez v0, :cond_7

    invoke-virtual {p1}, Llyiahf/vczjk/hy0;->OooO0oO()Z

    move-result v0

    if-eqz v0, :cond_0

    goto/16 :goto_2

    :cond_0
    iget-object v0, p1, Llyiahf/vczjk/hy0;->OooO0O0:Llyiahf/vczjk/hc3;

    iget-object v0, v0, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    iget-object v0, v0, Llyiahf/vczjk/ic3;->OooO00o:Ljava/lang/String;

    const-string v1, "Function"

    const/4 v2, 0x0

    invoke-static {v0, v1, v2}, Llyiahf/vczjk/z69;->Oooo0OO(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Z)Z

    move-result v1

    if-nez v1, :cond_1

    goto :goto_2

    :cond_1
    sget-object v1, Llyiahf/vczjk/dg3;->OooO0OO:Llyiahf/vczjk/dg3;

    iget-object p1, p1, Llyiahf/vczjk/hy0;->OooO00o:Llyiahf/vczjk/hc3;

    invoke-virtual {v1, v0, p1}, Llyiahf/vczjk/dg3;->OooO00o(Ljava/lang/String;Llyiahf/vczjk/hc3;)Llyiahf/vczjk/cg3;

    move-result-object v0

    if-nez v0, :cond_2

    goto :goto_2

    :cond_2
    iget-object v1, p0, Llyiahf/vczjk/ak0;->OooO0O0:Llyiahf/vczjk/dm5;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/dm5;->OooooO0(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/vh6;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/hw4;

    iget-object p1, p1, Llyiahf/vczjk/hw4;->OooOo00:Llyiahf/vczjk/o45;

    sget-object v1, Llyiahf/vczjk/hw4;->OooOo0o:[Llyiahf/vczjk/th4;

    aget-object v1, v1, v2

    invoke-static {p1, v1}, Llyiahf/vczjk/xr6;->OooOO0o(Llyiahf/vczjk/t26;Llyiahf/vczjk/th4;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/util/List;

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_3
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_4

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    instance-of v3, v2, Llyiahf/vczjk/hk0;

    if-eqz v3, :cond_3

    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_4
    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_5

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    goto :goto_1

    :cond_5
    invoke-static {p1}, Llyiahf/vczjk/d21;->oo000o(Ljava/util/List;)Ljava/lang/Object;

    move-result-object p1

    if-nez p1, :cond_6

    invoke-static {v1}, Llyiahf/vczjk/d21;->o00o0O(Ljava/util/List;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/hk0;

    new-instance v1, Llyiahf/vczjk/nf3;

    iget-object v2, p0, Llyiahf/vczjk/ak0;->OooO00o:Llyiahf/vczjk/q45;

    iget-object v3, v0, Llyiahf/vczjk/cg3;->OooO00o:Llyiahf/vczjk/bg3;

    iget v0, v0, Llyiahf/vczjk/cg3;->OooO0O0:I

    invoke-direct {v1, v2, p1, v3, v0}, Llyiahf/vczjk/nf3;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/hk0;Llyiahf/vczjk/bg3;I)V

    return-object v1

    :cond_6
    new-instance p1, Ljava/lang/ClassCastException;

    invoke-direct {p1}, Ljava/lang/ClassCastException;-><init>()V

    throw p1

    :cond_7
    :goto_2
    const/4 p1, 0x0

    return-object p1
.end method

.method public final OooO0OO(Llyiahf/vczjk/hc3;)Ljava/util/Collection;
    .locals 1

    const-string v0, "packageFqName"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object p1, Llyiahf/vczjk/gn2;->OooOOO0:Llyiahf/vczjk/gn2;

    return-object p1
.end method
