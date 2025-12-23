.class public final Llyiahf/vczjk/xx0;
.super Llyiahf/vczjk/y86;
.source "SourceFile"


# instance fields
.field public final OooOOo:Ljava/util/ArrayList;

.field public final OooOOo0:Llyiahf/vczjk/au1;

.field public final OooOOoo:Ljava/util/HashMap;

.field public OooOo:[B

.field public final OooOo0:Ljava/util/ArrayList;

.field public final OooOo00:Ljava/util/ArrayList;

.field public final OooOo0O:Ljava/util/ArrayList;

.field public OooOo0o:Llyiahf/vczjk/gt1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/au1;)V
    .locals 2

    const/4 v0, 0x1

    const/4 v1, -0x1

    invoke-direct {p0, v0, v1}, Llyiahf/vczjk/y86;-><init>(II)V

    if-eqz p1, :cond_0

    iput-object p1, p0, Llyiahf/vczjk/xx0;->OooOOo0:Llyiahf/vczjk/au1;

    new-instance p1, Ljava/util/ArrayList;

    const/16 v0, 0x14

    invoke-direct {p1, v0}, Ljava/util/ArrayList;-><init>(I)V

    iput-object p1, p0, Llyiahf/vczjk/xx0;->OooOOo:Ljava/util/ArrayList;

    new-instance p1, Ljava/util/HashMap;

    const/16 v1, 0x28

    invoke-direct {p1, v1}, Ljava/util/HashMap;-><init>(I)V

    iput-object p1, p0, Llyiahf/vczjk/xx0;->OooOOoo:Ljava/util/HashMap;

    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1, v0}, Ljava/util/ArrayList;-><init>(I)V

    iput-object p1, p0, Llyiahf/vczjk/xx0;->OooOo00:Ljava/util/ArrayList;

    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1, v0}, Ljava/util/ArrayList;-><init>(I)V

    iput-object p1, p0, Llyiahf/vczjk/xx0;->OooOo0:Ljava/util/ArrayList;

    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1, v0}, Ljava/util/ArrayList;-><init>(I)V

    iput-object p1, p0, Llyiahf/vczjk/xx0;->OooOo0O:Ljava/util/ArrayList;

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/xx0;->OooOo0o:Llyiahf/vczjk/gt1;

    return-void

    :cond_0
    new-instance p1, Ljava/lang/NullPointerException;

    const-string v0, "thisClass == null"

    invoke-direct {p1, v0}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public static OooOO0o(Llyiahf/vczjk/t92;Llyiahf/vczjk/ol0;Ljava/lang/String;Ljava/util/ArrayList;)V
    .locals 4

    invoke-virtual {p3}, Ljava/util/ArrayList;->size()I

    move-result v0

    if-nez v0, :cond_0

    goto :goto_1

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/ol0;->OooO0Oo()Z

    move-result v1

    const/4 v2, 0x0

    if-eqz v1, :cond_1

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v3, "  "

    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p2, ":"

    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p1, v2, p2}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    :cond_1
    move p2, v2

    :goto_0
    if-ge v2, v0, :cond_2

    invoke-virtual {p3, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/jn2;

    invoke-virtual {v1, p0, p1, p2, v2}, Llyiahf/vczjk/jn2;->OooO0O0(Llyiahf/vczjk/t92;Llyiahf/vczjk/ol0;II)I

    move-result p2

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_2
    :goto_1
    return-void
.end method

.method public static OooOOO(Llyiahf/vczjk/ol0;Ljava/lang/String;I)V
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/ol0;->OooO0Oo()Z

    move-result v0

    if-eqz v0, :cond_0

    const-string v0, "_size:"

    invoke-virtual {p1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    filled-new-array {p1, v0}, [Ljava/lang/Object;

    move-result-object p1

    const-string v0, "  %-21s %08x"

    invoke-static {v0, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/ol0;->OooO0OO(Ljava/lang/String;)V

    :cond_0
    invoke-virtual {p0, p2}, Llyiahf/vczjk/ol0;->OooOOO0(I)I

    return-void
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/rj5;I)V
    .locals 2

    new-instance p2, Llyiahf/vczjk/ol0;

    invoke-direct {p2}, Llyiahf/vczjk/ol0;-><init>()V

    iget-object p1, p1, Llyiahf/vczjk/bc8;->OooO0O0:Llyiahf/vczjk/t92;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/xx0;->OooOOO0(Llyiahf/vczjk/t92;Llyiahf/vczjk/ol0;)V

    iget p1, p2, Llyiahf/vczjk/ol0;->OooO0OO:I

    new-array v0, p1, [B

    iget-object p2, p2, Llyiahf/vczjk/ol0;->OooO0O0:[B

    const/4 v1, 0x0

    invoke-static {p2, v1, v0, v1, p1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    iput-object v0, p0, Llyiahf/vczjk/xx0;->OooOo:[B

    invoke-virtual {p0, p1}, Llyiahf/vczjk/y86;->OooOO0(I)V

    return-void
.end method

.method public final OooO00o(Llyiahf/vczjk/t92;)V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/xx0;->OooOOo:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/xx0;->OooOOOO()Llyiahf/vczjk/gt1;

    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/in2;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v2, p1, Llyiahf/vczjk/t92;->OooO0oo:Llyiahf/vczjk/ix2;

    iget-object v1, v1, Llyiahf/vczjk/in2;->OooOOO:Llyiahf/vczjk/lt1;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/ix2;->OooOOO0(Llyiahf/vczjk/lt1;)V

    goto :goto_0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/xx0;->OooOo00:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_1

    invoke-static {v0}, Ljava/util/Collections;->sort(Ljava/util/List;)V

    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/in2;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v2, p1, Llyiahf/vczjk/t92;->OooO0oo:Llyiahf/vczjk/ix2;

    iget-object v1, v1, Llyiahf/vczjk/in2;->OooOOO:Llyiahf/vczjk/lt1;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/ix2;->OooOOO0(Llyiahf/vczjk/lt1;)V

    goto :goto_1

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/xx0;->OooOo0:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_3

    invoke-static {v0}, Ljava/util/Collections;->sort(Ljava/util/List;)V

    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_2
    :goto_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_3

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/kn2;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v2, p1, Llyiahf/vczjk/t92;->OooO:Llyiahf/vczjk/bj5;

    iget-object v3, v1, Llyiahf/vczjk/kn2;->OooOOO:Llyiahf/vczjk/wt1;

    invoke-virtual {v2, v3}, Llyiahf/vczjk/bj5;->OooOOO0(Llyiahf/vczjk/wt1;)V

    iget-object v1, v1, Llyiahf/vczjk/kn2;->OooOOOO:Llyiahf/vczjk/x01;

    if-eqz v1, :cond_2

    iget-object v2, p1, Llyiahf/vczjk/t92;->OooO00o:Llyiahf/vczjk/rj5;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/rj5;->OooOO0O(Llyiahf/vczjk/y86;)V

    goto :goto_2

    :cond_3
    iget-object v0, p0, Llyiahf/vczjk/xx0;->OooOo0O:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_5

    invoke-static {v0}, Ljava/util/Collections;->sort(Ljava/util/List;)V

    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_4
    :goto_3
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_5

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/kn2;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v2, p1, Llyiahf/vczjk/t92;->OooO:Llyiahf/vczjk/bj5;

    iget-object v3, v1, Llyiahf/vczjk/kn2;->OooOOO:Llyiahf/vczjk/wt1;

    invoke-virtual {v2, v3}, Llyiahf/vczjk/bj5;->OooOOO0(Llyiahf/vczjk/wt1;)V

    iget-object v1, v1, Llyiahf/vczjk/kn2;->OooOOOO:Llyiahf/vczjk/x01;

    if-eqz v1, :cond_4

    iget-object v2, p1, Llyiahf/vczjk/t92;->OooO00o:Llyiahf/vczjk/rj5;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/rj5;->OooOO0O(Llyiahf/vczjk/y86;)V

    goto :goto_3

    :cond_5
    return-void
.end method

.method public final OooO0O0()Llyiahf/vczjk/i54;
    .locals 1

    sget-object v0, Llyiahf/vczjk/i54;->OooOo0O:Llyiahf/vczjk/i54;

    return-object v0
.end method

.method public final OooOO0O(Llyiahf/vczjk/t92;Llyiahf/vczjk/ol0;)V
    .locals 1

    invoke-virtual {p2}, Llyiahf/vczjk/ol0;->OooO0Oo()Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/xx0;->OooOOO0(Llyiahf/vczjk/t92;Llyiahf/vczjk/ol0;)V

    return-void

    :cond_0
    iget-object p1, p0, Llyiahf/vczjk/xx0;->OooOo:[B

    invoke-virtual {p2, p1}, Llyiahf/vczjk/ol0;->OooO0oo([B)V

    return-void
.end method

.method public final OooOOO0(Llyiahf/vczjk/t92;Llyiahf/vczjk/ol0;)V
    .locals 10

    invoke-virtual {p2}, Llyiahf/vczjk/ol0;->OooO0Oo()Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/y86;->OooO0oO()Ljava/lang/String;

    move-result-object v1

    iget-object v2, p0, Llyiahf/vczjk/xx0;->OooOOo0:Llyiahf/vczjk/au1;

    iget-object v2, v2, Llyiahf/vczjk/au1;->OooOOO0:Llyiahf/vczjk/p1a;

    invoke-virtual {v2}, Llyiahf/vczjk/p1a;->OooO00o()Ljava/lang/String;

    move-result-object v2

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, " class data for "

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    const/4 v2, 0x0

    invoke-virtual {p2, v2, v1}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/xx0;->OooOOo:Ljava/util/ArrayList;

    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    move-result v2

    const-string v3, "static_fields"

    invoke-static {p2, v3, v2}, Llyiahf/vczjk/xx0;->OooOOO(Llyiahf/vczjk/ol0;Ljava/lang/String;I)V

    iget-object v2, p0, Llyiahf/vczjk/xx0;->OooOo00:Ljava/util/ArrayList;

    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    move-result v4

    const-string v5, "instance_fields"

    invoke-static {p2, v5, v4}, Llyiahf/vczjk/xx0;->OooOOO(Llyiahf/vczjk/ol0;Ljava/lang/String;I)V

    iget-object v4, p0, Llyiahf/vczjk/xx0;->OooOo0:Ljava/util/ArrayList;

    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    move-result v6

    const-string v7, "direct_methods"

    invoke-static {p2, v7, v6}, Llyiahf/vczjk/xx0;->OooOOO(Llyiahf/vczjk/ol0;Ljava/lang/String;I)V

    iget-object v6, p0, Llyiahf/vczjk/xx0;->OooOo0O:Ljava/util/ArrayList;

    invoke-virtual {v6}, Ljava/util/ArrayList;->size()I

    move-result v8

    const-string v9, "virtual_methods"

    invoke-static {p2, v9, v8}, Llyiahf/vczjk/xx0;->OooOOO(Llyiahf/vczjk/ol0;Ljava/lang/String;I)V

    invoke-static {p1, p2, v3, v1}, Llyiahf/vczjk/xx0;->OooOO0o(Llyiahf/vczjk/t92;Llyiahf/vczjk/ol0;Ljava/lang/String;Ljava/util/ArrayList;)V

    invoke-static {p1, p2, v5, v2}, Llyiahf/vczjk/xx0;->OooOO0o(Llyiahf/vczjk/t92;Llyiahf/vczjk/ol0;Ljava/lang/String;Ljava/util/ArrayList;)V

    invoke-static {p1, p2, v7, v4}, Llyiahf/vczjk/xx0;->OooOO0o(Llyiahf/vczjk/t92;Llyiahf/vczjk/ol0;Ljava/lang/String;Ljava/util/ArrayList;)V

    invoke-static {p1, p2, v9, v6}, Llyiahf/vczjk/xx0;->OooOO0o(Llyiahf/vczjk/t92;Llyiahf/vczjk/ol0;Ljava/lang/String;Ljava/util/ArrayList;)V

    if-eqz v0, :cond_1

    invoke-virtual {p2}, Llyiahf/vczjk/ol0;->OooO0o0()V

    :cond_1
    return-void
.end method

.method public final OooOOOO()Llyiahf/vczjk/gt1;
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/xx0;->OooOo0o:Llyiahf/vczjk/gt1;

    if-nez v0, :cond_6

    iget-object v0, p0, Llyiahf/vczjk/xx0;->OooOOo:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v1

    if-eqz v1, :cond_6

    invoke-static {v0}, Ljava/util/Collections;->sort(Ljava/util/List;)V

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v1

    :goto_0
    iget-object v2, p0, Llyiahf/vczjk/xx0;->OooOOoo:Ljava/util/HashMap;

    if-lez v1, :cond_2

    add-int/lit8 v3, v1, -0x1

    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/in2;

    invoke-virtual {v2, v3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/hj1;

    instance-of v4, v3, Llyiahf/vczjk/tt1;

    if-eqz v4, :cond_0

    check-cast v3, Llyiahf/vczjk/tt1;

    invoke-virtual {v3}, Llyiahf/vczjk/tt1;->OooO0oo()J

    move-result-wide v3

    const-wide/16 v5, 0x0

    cmp-long v3, v3, v5

    if-eqz v3, :cond_1

    goto :goto_1

    :cond_0
    if-eqz v3, :cond_1

    goto :goto_1

    :cond_1
    add-int/lit8 v1, v1, -0x1

    goto :goto_0

    :cond_2
    :goto_1
    if-nez v1, :cond_3

    const/4 v0, 0x0

    goto :goto_5

    :cond_3
    new-instance v3, Llyiahf/vczjk/ft1;

    invoke-direct {v3, v1}, Llyiahf/vczjk/x13;-><init>(I)V

    const/4 v4, 0x0

    move v5, v4

    :goto_2
    if-ge v5, v1, :cond_5

    invoke-virtual {v0, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/in2;

    invoke-virtual {v2, v6}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/hj1;

    if-nez v7, :cond_4

    iget-object v6, v6, Llyiahf/vczjk/in2;->OooOOO:Llyiahf/vczjk/lt1;

    invoke-virtual {v6}, Llyiahf/vczjk/lt1;->getType()Llyiahf/vczjk/p1a;

    move-result-object v6

    iget v7, v6, Llyiahf/vczjk/p1a;->OooOOO:I

    packed-switch v7, :pswitch_data_0

    new-instance v0, Ljava/lang/UnsupportedOperationException;

    invoke-virtual {v6}, Llyiahf/vczjk/p1a;->OooO00o()Ljava/lang/String;

    move-result-object v1

    const-string v2, "no zero for type: "

    invoke-static {v2, v1}, Llyiahf/vczjk/u81;->OooOo(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw v0

    :pswitch_0
    sget-object v6, Llyiahf/vczjk/qt1;->OooOOO0:Llyiahf/vczjk/qt1;

    :goto_3
    move-object v7, v6

    goto :goto_4

    :pswitch_1
    sget-object v6, Llyiahf/vczjk/yt1;->OooOOO:Llyiahf/vczjk/yt1;

    goto :goto_3

    :pswitch_2
    sget-object v6, Llyiahf/vczjk/ut1;->OooOOO:Llyiahf/vczjk/ut1;

    goto :goto_3

    :pswitch_3
    sget-object v6, Llyiahf/vczjk/pt1;->OooOOOO:Llyiahf/vczjk/pt1;

    goto :goto_3

    :pswitch_4
    sget-object v6, Llyiahf/vczjk/mt1;->OooOOO:Llyiahf/vczjk/mt1;

    goto :goto_3

    :pswitch_5
    sget-object v6, Llyiahf/vczjk/kt1;->OooOOO:Llyiahf/vczjk/kt1;

    goto :goto_3

    :pswitch_6
    sget-object v6, Llyiahf/vczjk/jt1;->OooOOO:Llyiahf/vczjk/jt1;

    goto :goto_3

    :pswitch_7
    sget-object v6, Llyiahf/vczjk/it1;->OooOOO:Llyiahf/vczjk/it1;

    goto :goto_3

    :pswitch_8
    sget-object v6, Llyiahf/vczjk/ht1;->OooOOO:Llyiahf/vczjk/ht1;

    goto :goto_3

    :cond_4
    :goto_4
    invoke-virtual {v3, v5, v7}, Llyiahf/vczjk/x13;->OooO0o(ILjava/lang/Object;)V

    add-int/lit8 v5, v5, 0x1

    goto :goto_2

    :cond_5
    iput-boolean v4, v3, Llyiahf/vczjk/wu0;->OooOOO0:Z

    new-instance v0, Llyiahf/vczjk/gt1;

    invoke-direct {v0, v3}, Llyiahf/vczjk/gt1;-><init>(Llyiahf/vczjk/ft1;)V

    :goto_5
    iput-object v0, p0, Llyiahf/vczjk/xx0;->OooOo0o:Llyiahf/vczjk/gt1;

    :cond_6
    iget-object v0, p0, Llyiahf/vczjk/xx0;->OooOo0o:Llyiahf/vczjk/gt1;

    return-object v0

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final OooOOOo()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/xx0;->OooOOo:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/xx0;->OooOo00:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/xx0;->OooOo0:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/xx0;->OooOo0O:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method
