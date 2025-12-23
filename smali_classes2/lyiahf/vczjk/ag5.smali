.class public final Llyiahf/vczjk/ag5;
.super Ljava/lang/Object;

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I

.field public final OooOOOO:Ljava/lang/Object;

.field public final OooOOOo:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/cg5;Llyiahf/vczjk/sg3;II)V
    .locals 0

    iput p4, p0, Llyiahf/vczjk/ag5;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/ag5;->OooOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/ag5;->OooOOOO:Ljava/lang/Object;

    iput p3, p0, Llyiahf/vczjk/ag5;->OooOOOo:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/di4;ILlyiahf/vczjk/kp4;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Llyiahf/vczjk/ag5;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ag5;->OooOOO:Ljava/lang/Object;

    iput p2, p0, Llyiahf/vczjk/ag5;->OooOOOo:I

    iput-object p3, p0, Llyiahf/vczjk/ag5;->OooOOOO:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 4

    iget v0, p0, Llyiahf/vczjk/ag5;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/ag5;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/di4;

    iget-object v1, v0, Llyiahf/vczjk/di4;->OooO0O0:Llyiahf/vczjk/wm7;

    if-eqz v1, :cond_0

    invoke-virtual {v1}, Llyiahf/vczjk/wm7;->OooO00o()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/reflect/Type;

    goto :goto_0

    :cond_0
    const/4 v1, 0x0

    :goto_0
    instance-of v2, v1, Ljava/lang/Class;

    if-eqz v2, :cond_2

    check-cast v1, Ljava/lang/Class;

    invoke-virtual {v1}, Ljava/lang/Class;->isArray()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-virtual {v1}, Ljava/lang/Class;->getComponentType()Ljava/lang/Class;

    move-result-object v0

    goto :goto_1

    :cond_1
    const-class v0, Ljava/lang/Object;

    :goto_1
    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    goto :goto_3

    :cond_2
    instance-of v2, v1, Ljava/lang/reflect/GenericArrayType;

    iget v3, p0, Llyiahf/vczjk/ag5;->OooOOOo:I

    if-eqz v2, :cond_4

    if-nez v3, :cond_3

    check-cast v1, Ljava/lang/reflect/GenericArrayType;

    invoke-interface {v1}, Ljava/lang/reflect/GenericArrayType;->getGenericComponentType()Ljava/lang/reflect/Type;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    goto :goto_3

    :cond_3
    new-instance v1, Llyiahf/vczjk/es1;

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "Array type has been queried for a non-0th argument: "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {v1, v0}, Llyiahf/vczjk/es1;-><init>(Ljava/lang/String;)V

    throw v1

    :cond_4
    instance-of v1, v1, Ljava/lang/reflect/ParameterizedType;

    if-eqz v1, :cond_7

    iget-object v0, p0, Llyiahf/vczjk/ag5;->OooOOOO:Ljava/lang/Object;

    invoke-interface {v0}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/util/List;

    invoke-interface {v0, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/reflect/Type;

    instance-of v1, v0, Ljava/lang/reflect/WildcardType;

    if-nez v1, :cond_5

    goto :goto_3

    :cond_5
    check-cast v0, Ljava/lang/reflect/WildcardType;

    invoke-interface {v0}, Ljava/lang/reflect/WildcardType;->getLowerBounds()[Ljava/lang/reflect/Type;

    move-result-object v1

    const-string v2, "getLowerBounds(...)"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v1}, Llyiahf/vczjk/sy;->o000OOo([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/reflect/Type;

    if-nez v1, :cond_6

    invoke-interface {v0}, Ljava/lang/reflect/WildcardType;->getUpperBounds()[Ljava/lang/reflect/Type;

    move-result-object v0

    const-string v1, "getUpperBounds(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v0}, Llyiahf/vczjk/sy;->oo0o0Oo([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/reflect/Type;

    goto :goto_2

    :cond_6
    move-object v0, v1

    :goto_2
    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    :goto_3
    return-object v0

    :cond_7
    new-instance v1, Llyiahf/vczjk/es1;

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "Non-generic type has been queried for arguments: "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {v1, v0}, Llyiahf/vczjk/es1;-><init>(Ljava/lang/String;)V

    throw v1

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/ag5;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/cg5;

    iget-object v1, v0, Llyiahf/vczjk/cg5;->OooO00o:Llyiahf/vczjk/u72;

    iget-object v1, v1, Llyiahf/vczjk/u72;->OooO0OO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/v02;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/cg5;->OooO00o(Llyiahf/vczjk/v02;)Llyiahf/vczjk/yd7;

    move-result-object v1

    if-eqz v1, :cond_8

    iget-object v0, v0, Llyiahf/vczjk/cg5;->OooO00o:Llyiahf/vczjk/u72;

    iget-object v0, v0, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s72;

    iget-object v0, v0, Llyiahf/vczjk/s72;->OooO0o0:Llyiahf/vczjk/hn;

    iget-object v2, p0, Llyiahf/vczjk/ag5;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/sg3;

    iget v3, p0, Llyiahf/vczjk/ag5;->OooOOOo:I

    invoke-interface {v0, v1, v2, v3}, Llyiahf/vczjk/zn;->OooO0OO(Llyiahf/vczjk/yd7;Llyiahf/vczjk/sg3;I)Ljava/util/List;

    move-result-object v0

    goto :goto_4

    :cond_8
    const/4 v0, 0x0

    :goto_4
    if-nez v0, :cond_9

    sget-object v0, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    :cond_9
    return-object v0

    :pswitch_1
    iget-object v0, p0, Llyiahf/vczjk/ag5;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/cg5;

    iget-object v1, v0, Llyiahf/vczjk/cg5;->OooO00o:Llyiahf/vczjk/u72;

    iget-object v1, v1, Llyiahf/vczjk/u72;->OooO0OO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/v02;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/cg5;->OooO00o(Llyiahf/vczjk/v02;)Llyiahf/vczjk/yd7;

    move-result-object v1

    if-eqz v1, :cond_a

    iget-object v0, v0, Llyiahf/vczjk/cg5;->OooO00o:Llyiahf/vczjk/u72;

    iget-object v0, v0, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s72;

    iget-object v0, v0, Llyiahf/vczjk/s72;->OooO0o0:Llyiahf/vczjk/hn;

    iget-object v2, p0, Llyiahf/vczjk/ag5;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/sg3;

    iget v3, p0, Llyiahf/vczjk/ag5;->OooOOOo:I

    invoke-interface {v0, v1, v2, v3}, Llyiahf/vczjk/zn;->OooOOOo(Llyiahf/vczjk/yd7;Llyiahf/vczjk/sg3;I)Ljava/util/List;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/d21;->o000OO(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object v0

    goto :goto_5

    :cond_a
    const/4 v0, 0x0

    :goto_5
    if-nez v0, :cond_b

    sget-object v0, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    :cond_b
    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
