.class public final Llyiahf/vczjk/o82;
.super Ljava/lang/Object;

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/q82;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/q82;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/o82;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/o82;->OooOOO:Llyiahf/vczjk/q82;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    iget v0, p0, Llyiahf/vczjk/o82;->OooOOO0:I

    check-cast p1, Llyiahf/vczjk/qt5;

    packed-switch v0, :pswitch_data_0

    const-string v0, "it"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/o82;->OooOOO:Llyiahf/vczjk/q82;

    iget-object v1, v0, Llyiahf/vczjk/q82;->OooO0OO:Ljava/util/LinkedHashMap;

    invoke-virtual {v1, p1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, [B

    if-nez p1, :cond_0

    goto :goto_0

    :cond_0
    new-instance v1, Ljava/io/ByteArrayInputStream;

    invoke-direct {v1, p1}, Ljava/io/ByteArrayInputStream;-><init>([B)V

    iget-object p1, v0, Llyiahf/vczjk/q82;->OooO:Llyiahf/vczjk/r82;

    iget-object v0, p1, Llyiahf/vczjk/r82;->OooO0O0:Llyiahf/vczjk/u72;

    iget-object v0, v0, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s72;

    iget-object v0, v0, Llyiahf/vczjk/s72;->OooOOOo:Llyiahf/vczjk/iu2;

    sget-object v2, Llyiahf/vczjk/jd7;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {v2, v1, v0}, Llyiahf/vczjk/je4;->OooO0OO(Ljava/io/ByteArrayInputStream;Llyiahf/vczjk/iu2;)Llyiahf/vczjk/pi5;

    move-result-object v0

    move-object v7, v0

    check-cast v7, Llyiahf/vczjk/jd7;

    if-nez v7, :cond_1

    :goto_0
    const/4 p1, 0x0

    goto/16 :goto_6

    :cond_1
    iget-object p1, p1, Llyiahf/vczjk/r82;->OooO0O0:Llyiahf/vczjk/u72;

    iget-object p1, p1, Llyiahf/vczjk/u72;->OooO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/cg5;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v7}, Llyiahf/vczjk/jd7;->OooOooO()Ljava/util/List;

    move-result-object v0

    const-string v1, "getAnnotationList(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Ljava/util/ArrayList;

    const/16 v2, 0xa

    invoke-static {v0, v2}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v2

    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    iget-object v12, p1, Llyiahf/vczjk/cg5;->OooO00o:Llyiahf/vczjk/u72;

    if-eqz v2, :cond_2

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/wb7;

    invoke-static {v2}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-object v3, v12, Llyiahf/vczjk/u72;->OooO0O0:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/rt5;

    iget-object v4, p1, Llyiahf/vczjk/cg5;->OooO0O0:Llyiahf/vczjk/n62;

    invoke-virtual {v4, v2, v3}, Llyiahf/vczjk/n62;->o00ooo(Llyiahf/vczjk/wb7;Llyiahf/vczjk/rt5;)Llyiahf/vczjk/vn;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_2
    invoke-virtual {v1}, Ljava/util/ArrayList;->isEmpty()Z

    move-result p1

    if-eqz p1, :cond_3

    sget-object p1, Llyiahf/vczjk/qp3;->OooOOO0:Llyiahf/vczjk/jo;

    :goto_2
    move-object v4, p1

    goto :goto_3

    :cond_3
    new-instance p1, Llyiahf/vczjk/po;

    const/4 v0, 0x0

    invoke-direct {p1, v0, v1}, Llyiahf/vczjk/po;-><init>(ILjava/util/List;)V

    goto :goto_2

    :goto_3
    sget-object p1, Llyiahf/vczjk/c23;->OooO0Oo:Llyiahf/vczjk/a23;

    invoke-virtual {v7}, Llyiahf/vczjk/jd7;->getFlags()I

    move-result v0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/a23;->OooOO0o(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/vd7;

    invoke-static {p1}, Llyiahf/vczjk/er8;->OooOO0o(Llyiahf/vczjk/vd7;)Llyiahf/vczjk/q72;

    move-result-object v6

    new-instance v1, Llyiahf/vczjk/v82;

    iget-object p1, v12, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/s72;

    iget-object v2, p1, Llyiahf/vczjk/s72;->OooO00o:Llyiahf/vczjk/q45;

    invoke-virtual {v7}, Llyiahf/vczjk/jd7;->Oooo00O()I

    move-result p1

    iget-object v0, v12, Llyiahf/vczjk/u72;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/rt5;

    invoke-static {v0, p1}, Llyiahf/vczjk/l4a;->OooOo(Llyiahf/vczjk/rt5;I)Llyiahf/vczjk/qt5;

    move-result-object v5

    iget-object p1, v12, Llyiahf/vczjk/u72;->OooO0Oo:Ljava/lang/Object;

    move-object v9, p1

    check-cast v9, Llyiahf/vczjk/h87;

    iget-object p1, v12, Llyiahf/vczjk/u72;->OooO0o0:Ljava/lang/Object;

    move-object v10, p1

    check-cast v10, Llyiahf/vczjk/xea;

    iget-object p1, v12, Llyiahf/vczjk/u72;->OooO0oO:Ljava/lang/Object;

    move-object v11, p1

    check-cast v11, Llyiahf/vczjk/ce4;

    iget-object p1, v12, Llyiahf/vczjk/u72;->OooO0OO:Ljava/lang/Object;

    move-object v3, p1

    check-cast v3, Llyiahf/vczjk/v02;

    iget-object p1, v12, Llyiahf/vczjk/u72;->OooO0O0:Ljava/lang/Object;

    move-object v8, p1

    check-cast v8, Llyiahf/vczjk/rt5;

    invoke-direct/range {v1 .. v11}, Llyiahf/vczjk/v82;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/v02;Llyiahf/vczjk/ko;Llyiahf/vczjk/qt5;Llyiahf/vczjk/q72;Llyiahf/vczjk/jd7;Llyiahf/vczjk/rt5;Llyiahf/vczjk/h87;Llyiahf/vczjk/xea;Llyiahf/vczjk/ce4;)V

    invoke-virtual {v7}, Llyiahf/vczjk/jd7;->Oooo00o()Ljava/util/List;

    move-result-object p1

    const-string v0, "getTypeParameterList(...)"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v12, v1, p1}, Llyiahf/vczjk/u72;->OooO0O0(Llyiahf/vczjk/u72;Llyiahf/vczjk/y02;Ljava/util/List;)Llyiahf/vczjk/u72;

    move-result-object p1

    iget-object p1, p1, Llyiahf/vczjk/u72;->OooO0oo:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/t3a;

    invoke-virtual {p1}, Llyiahf/vczjk/t3a;->OooO0O0()Ljava/util/List;

    move-result-object v0

    invoke-virtual {v7}, Llyiahf/vczjk/jd7;->Oooo0oo()Z

    move-result v2

    if-eqz v2, :cond_4

    invoke-virtual {v7}, Llyiahf/vczjk/jd7;->Oooo0()Llyiahf/vczjk/hd7;

    move-result-object v2

    const-string v3, "getUnderlyingType(...)"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    goto :goto_4

    :cond_4
    invoke-virtual {v7}, Llyiahf/vczjk/jd7;->Oooo()Z

    move-result v2

    if-eqz v2, :cond_7

    invoke-virtual {v7}, Llyiahf/vczjk/jd7;->Oooo0O0()I

    move-result v2

    invoke-virtual {v9, v2}, Llyiahf/vczjk/h87;->OooO0Oo(I)Llyiahf/vczjk/hd7;

    move-result-object v2

    :goto_4
    const/4 v3, 0x0

    invoke-virtual {p1, v2, v3}, Llyiahf/vczjk/t3a;->OooO0Oo(Llyiahf/vczjk/hd7;Z)Llyiahf/vczjk/dp8;

    move-result-object v2

    invoke-virtual {v7}, Llyiahf/vczjk/jd7;->Oooo0OO()Z

    move-result v4

    if-eqz v4, :cond_5

    invoke-virtual {v7}, Llyiahf/vczjk/jd7;->OooOooo()Llyiahf/vczjk/hd7;

    move-result-object v4

    const-string v5, "getExpandedType(...)"

    invoke-static {v4, v5}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    goto :goto_5

    :cond_5
    invoke-virtual {v7}, Llyiahf/vczjk/jd7;->Oooo0o0()Z

    move-result v4

    if-eqz v4, :cond_6

    invoke-virtual {v7}, Llyiahf/vczjk/jd7;->Oooo000()I

    move-result v4

    invoke-virtual {v9, v4}, Llyiahf/vczjk/h87;->OooO0Oo(I)Llyiahf/vczjk/hd7;

    move-result-object v4

    :goto_5
    invoke-virtual {p1, v4, v3}, Llyiahf/vczjk/t3a;->OooO0Oo(Llyiahf/vczjk/hd7;Z)Llyiahf/vczjk/dp8;

    move-result-object p1

    invoke-virtual {v1, v0, v2, p1}, Llyiahf/vczjk/v82;->o0000O(Ljava/util/List;Llyiahf/vczjk/dp8;Llyiahf/vczjk/dp8;)V

    move-object p1, v1

    :goto_6
    return-object p1

    :cond_6
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "No expandedType in ProtoBuf.TypeAlias"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_7
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "No underlyingType in ProtoBuf.TypeAlias"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :pswitch_0
    const-string v0, "it"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/o82;->OooOOO:Llyiahf/vczjk/q82;

    iget-object v1, v0, Llyiahf/vczjk/q82;->OooO0O0:Ljava/util/LinkedHashMap;

    sget-object v2, Llyiahf/vczjk/xc7;->OooOOO:Llyiahf/vczjk/je4;

    const-string v3, "PARSER"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v1, p1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, [B

    iget-object v0, v0, Llyiahf/vczjk/q82;->OooO:Llyiahf/vczjk/r82;

    if-eqz v1, :cond_8

    new-instance v3, Ljava/io/ByteArrayInputStream;

    invoke-direct {v3, v1}, Ljava/io/ByteArrayInputStream;-><init>([B)V

    new-instance v1, Llyiahf/vczjk/o0O0000O;

    const/4 v4, 0x1

    invoke-direct {v1, v2, v3, v4, v0}, Llyiahf/vczjk/o0O0000O;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-static {v1}, Llyiahf/vczjk/ag8;->Oooo0o0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/wf8;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/ag8;->OoooO00(Llyiahf/vczjk/wf8;)Ljava/util/List;

    move-result-object v1

    goto :goto_7

    :cond_8
    sget-object v1, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    :goto_7
    new-instance v2, Ljava/util/ArrayList;

    invoke-interface {v1}, Ljava/util/Collection;->size()I

    move-result v3

    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_8
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_9

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/xc7;

    iget-object v4, v0, Llyiahf/vczjk/r82;->OooO0O0:Llyiahf/vczjk/u72;

    iget-object v4, v4, Llyiahf/vczjk/u72;->OooO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/cg5;

    invoke-static {v3}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v4, v3}, Llyiahf/vczjk/cg5;->OooO0o(Llyiahf/vczjk/xc7;)Llyiahf/vczjk/t82;

    move-result-object v3

    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_8

    :cond_9
    invoke-virtual {v0, v2, p1}, Llyiahf/vczjk/r82;->OooOO0O(Ljava/util/ArrayList;Llyiahf/vczjk/qt5;)V

    invoke-static {v2}, Llyiahf/vczjk/t51;->OooOo0(Ljava/util/ArrayList;)Ljava/util/List;

    move-result-object p1

    return-object p1

    :pswitch_1
    const-string v0, "it"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/o82;->OooOOO:Llyiahf/vczjk/q82;

    iget-object v1, v0, Llyiahf/vczjk/q82;->OooO00o:Ljava/util/LinkedHashMap;

    sget-object v2, Llyiahf/vczjk/pc7;->OooOOO:Llyiahf/vczjk/je4;

    const-string v3, "PARSER"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v1, p1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, [B

    iget-object v0, v0, Llyiahf/vczjk/q82;->OooO:Llyiahf/vczjk/r82;

    if-eqz v1, :cond_a

    new-instance v3, Ljava/io/ByteArrayInputStream;

    invoke-direct {v3, v1}, Ljava/io/ByteArrayInputStream;-><init>([B)V

    new-instance v1, Llyiahf/vczjk/o0O0000O;

    const/4 v4, 0x1

    invoke-direct {v1, v2, v3, v4, v0}, Llyiahf/vczjk/o0O0000O;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-static {v1}, Llyiahf/vczjk/ag8;->Oooo0o0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/wf8;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/ag8;->OoooO00(Llyiahf/vczjk/wf8;)Ljava/util/List;

    move-result-object v1

    goto :goto_9

    :cond_a
    sget-object v1, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    :goto_9
    new-instance v2, Ljava/util/ArrayList;

    invoke-interface {v1}, Ljava/util/Collection;->size()I

    move-result v3

    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :cond_b
    :goto_a
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_d

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/pc7;

    iget-object v4, v0, Llyiahf/vczjk/r82;->OooO0O0:Llyiahf/vczjk/u72;

    iget-object v4, v4, Llyiahf/vczjk/u72;->OooO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/cg5;

    invoke-static {v3}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v4, v3}, Llyiahf/vczjk/cg5;->OooO0o0(Llyiahf/vczjk/pc7;)Llyiahf/vczjk/u82;

    move-result-object v3

    invoke-virtual {v0, v3}, Llyiahf/vczjk/r82;->OooOOo(Llyiahf/vczjk/u82;)Z

    move-result v4

    if-eqz v4, :cond_c

    goto :goto_b

    :cond_c
    const/4 v3, 0x0

    :goto_b
    if-eqz v3, :cond_b

    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_a

    :cond_d
    invoke-virtual {v0, v2, p1}, Llyiahf/vczjk/r82;->OooOO0(Ljava/util/ArrayList;Llyiahf/vczjk/qt5;)V

    invoke-static {v2}, Llyiahf/vczjk/t51;->OooOo0(Ljava/util/ArrayList;)Ljava/util/List;

    move-result-object p1

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
