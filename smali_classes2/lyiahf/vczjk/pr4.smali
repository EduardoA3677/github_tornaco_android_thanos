.class public final Llyiahf/vczjk/pr4;
.super Ljava/lang/Object;

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/rr4;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/rr4;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/pr4;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/pr4;->OooOOO:Llyiahf/vczjk/rr4;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 4

    iget v0, p0, Llyiahf/vczjk/pr4;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/pr4;->OooOOO:Llyiahf/vczjk/rr4;

    invoke-virtual {v0}, Llyiahf/vczjk/ds4;->OooO00o()Ljava/util/Set;

    move-result-object v1

    invoke-virtual {v0}, Llyiahf/vczjk/ds4;->OooO0oO()Ljava/util/Set;

    move-result-object v0

    check-cast v0, Ljava/lang/Iterable;

    invoke-static {v1, v0}, Llyiahf/vczjk/mh8;->OoooOO0(Ljava/util/Set;Ljava/lang/Iterable;)Ljava/util/LinkedHashSet;

    move-result-object v0

    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/pr4;->OooOOO:Llyiahf/vczjk/rr4;

    iget-object v0, v0, Llyiahf/vczjk/rr4;->OooOOOO:Llyiahf/vczjk/cm7;

    invoke-virtual {v0}, Llyiahf/vczjk/cm7;->OooO0O0()Ljava/util/List;

    move-result-object v0

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_1

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    move-object v3, v2

    check-cast v3, Llyiahf/vczjk/im7;

    iget-object v3, v3, Llyiahf/vczjk/im7;->OooO00o:Ljava/lang/reflect/Field;

    invoke-virtual {v3}, Ljava/lang/reflect/Field;->isEnumConstant()Z

    move-result v3

    if-eqz v3, :cond_0

    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_1
    const/16 v0, 0xa

    invoke-static {v1, v0}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v0

    invoke-static {v0}, Llyiahf/vczjk/lc5;->o00oO0o(I)I

    move-result v0

    const/16 v2, 0x10

    if-ge v0, v2, :cond_2

    move v0, v2

    :cond_2
    new-instance v2, Ljava/util/LinkedHashMap;

    invoke-direct {v2, v0}, Ljava/util/LinkedHashMap;-><init>(I)V

    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_3

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    move-object v3, v1

    check-cast v3, Llyiahf/vczjk/im7;

    invoke-virtual {v3}, Llyiahf/vczjk/km7;->OooO0OO()Llyiahf/vczjk/qt5;

    move-result-object v3

    invoke-interface {v2, v3, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_1

    :cond_3
    return-object v2

    :pswitch_1
    iget-object v0, p0, Llyiahf/vczjk/pr4;->OooOOO:Llyiahf/vczjk/rr4;

    iget-object v0, v0, Llyiahf/vczjk/rr4;->OooOOOO:Llyiahf/vczjk/cm7;

    iget-object v0, v0, Llyiahf/vczjk/cm7;->OooO00o:Ljava/lang/Class;

    invoke-virtual {v0}, Ljava/lang/Class;->getDeclaredClasses()[Ljava/lang/Class;

    move-result-object v0

    const-string v1, "getDeclaredClasses(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v0}, Llyiahf/vczjk/sy;->Oooooo([Ljava/lang/Object;)Llyiahf/vczjk/wf8;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/iu6;->OooOOoo:Llyiahf/vczjk/iu6;

    new-instance v2, Llyiahf/vczjk/e13;

    const/4 v3, 0x0

    invoke-direct {v2, v0, v3, v1}, Llyiahf/vczjk/e13;-><init>(Llyiahf/vczjk/wf8;ZLlyiahf/vczjk/oe3;)V

    sget-object v0, Llyiahf/vczjk/iu6;->OooOo00:Llyiahf/vczjk/iu6;

    invoke-static {v2, v0}, Llyiahf/vczjk/ag8;->Oooo(Llyiahf/vczjk/wf8;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/e13;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/ag8;->OoooO00(Llyiahf/vczjk/wf8;)Ljava/util/List;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/d21;->o0000OOo(Ljava/lang/Iterable;)Ljava/util/Set;

    move-result-object v0

    return-object v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
