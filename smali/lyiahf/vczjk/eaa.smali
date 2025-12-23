.class public final Llyiahf/vczjk/eaa;
.super Llyiahf/vczjk/m49;
.source "SourceFile"


# static fields
.field public static final OooOOOO:Llyiahf/vczjk/eaa;

.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected final _nonMerging:Z


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/eaa;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/eaa;-><init>(Z)V

    sput-object v0, Llyiahf/vczjk/eaa;->OooOOOO:Llyiahf/vczjk/eaa;

    return-void
.end method

.method public constructor <init>(Z)V
    .locals 1

    const-class v0, Ljava/lang/Object;

    invoke-direct {p0, v0}, Llyiahf/vczjk/m49;-><init>(Ljava/lang/Class;)V

    iput-boolean p1, p0, Llyiahf/vczjk/eaa;->_nonMerging:Z

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 8

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0OoOo0()I

    move-result v0

    const/4 v1, 0x0

    const/4 v2, 0x2

    packed-switch v0, :pswitch_data_0

    :pswitch_0
    const-class v0, Ljava/lang/Object;

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/v72;->o000000o(Ljava/lang/Class;Llyiahf/vczjk/eb4;)V

    throw v1

    :pswitch_1
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o000OOo()Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :pswitch_2
    return-object v1

    :pswitch_3
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    return-object p1

    :pswitch_4
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object p1

    :pswitch_5
    sget-object v0, Llyiahf/vczjk/w72;->OooOOO0:Llyiahf/vczjk/w72;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result p1

    if-eqz p1, :cond_0

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o00oO0o()Ljava/math/BigDecimal;

    move-result-object p1

    return-object p1

    :cond_0
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o00000oo()Ljava/lang/Number;

    move-result-object p1

    return-object p1

    :pswitch_6
    sget v0, Llyiahf/vczjk/m49;->OooOOO0:I

    invoke-virtual {p1, v0}, Llyiahf/vczjk/v72;->o00000oO(I)Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-static {p1, p2}, Llyiahf/vczjk/m49;->OooOOo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Number;

    move-result-object p1

    return-object p1

    :cond_1
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o00000oo()Ljava/lang/Number;

    move-result-object p1

    return-object p1

    :pswitch_7
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    move-result-object p1

    return-object p1

    :pswitch_8
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/gc4;->OooOOo0:Llyiahf/vczjk/gc4;

    if-ne v0, v1, :cond_3

    sget-object p2, Llyiahf/vczjk/w72;->OooOOOo:Llyiahf/vczjk/w72;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result p1

    if-eqz p1, :cond_2

    sget-object p1, Llyiahf/vczjk/faa;->OooOOOO:[Ljava/lang/Object;

    return-object p1

    :cond_2
    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1, v2}, Ljava/util/ArrayList;-><init>(I)V

    return-object p1

    :cond_3
    sget-object v0, Llyiahf/vczjk/w72;->OooOOOo:Llyiahf/vczjk/w72;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result v0

    const/4 v3, 0x0

    if-eqz v0, :cond_6

    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o0000oO()Llyiahf/vczjk/ie;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/ie;->OooOO0o()[Ljava/lang/Object;

    move-result-object v1

    move v2, v3

    :goto_0
    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/eaa;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v4

    array-length v5, v1

    if-lt v2, v5, :cond_4

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ie;->OooO0o0([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object v1

    move v2, v3

    :cond_4
    add-int/lit8 v5, v2, 0x1

    aput-object v4, v1, v2

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v2

    sget-object v4, Llyiahf/vczjk/gc4;->OooOOo0:Llyiahf/vczjk/gc4;

    if-ne v2, v4, :cond_5

    invoke-virtual {v0, v5, v1}, Llyiahf/vczjk/ie;->OooO0oO(I[Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_5
    move v2, v5

    goto :goto_0

    :cond_6
    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/eaa;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v0

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v4

    if-ne v4, v1, :cond_7

    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1, v2}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-object p1

    :cond_7
    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/eaa;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v4

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v5

    if-ne v5, v1, :cond_8

    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1, v2}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    invoke-virtual {p1, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-object p1

    :cond_8
    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o0000oO()Llyiahf/vczjk/ie;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/ie;->OooOO0o()[Ljava/lang/Object;

    move-result-object v5

    aput-object v0, v5, v3

    const/4 v0, 0x1

    aput-object v4, v5, v0

    move v4, v2

    :goto_1
    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/eaa;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v6

    add-int/2addr v2, v0

    array-length v7, v5

    if-lt v4, v7, :cond_9

    invoke-virtual {v1, v5}, Llyiahf/vczjk/ie;->OooO0o0([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object v4

    move-object v5, v4

    move v4, v3

    :cond_9
    add-int/lit8 v7, v4, 0x1

    aput-object v6, v5, v4

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v4

    sget-object v6, Llyiahf/vczjk/gc4;->OooOOo0:Llyiahf/vczjk/gc4;

    if-ne v4, v6, :cond_a

    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1, v2}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {v1, v5, v7, p1}, Llyiahf/vczjk/ie;->OooO0o([Ljava/lang/Object;ILjava/util/ArrayList;)V

    return-object p1

    :cond_a
    move v4, v7

    goto :goto_1

    :pswitch_9
    new-instance p1, Ljava/util/LinkedHashMap;

    invoke-direct {p1, v2}, Ljava/util/LinkedHashMap;-><init>(I)V

    return-object p1

    :pswitch_a
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/gc4;->OooOOOO:Llyiahf/vczjk/gc4;

    if-ne v0, v1, :cond_b

    new-instance p1, Ljava/util/LinkedHashMap;

    invoke-direct {p1, v2}, Ljava/util/LinkedHashMap;-><init>(I)V

    return-object p1

    :cond_b
    :pswitch_b
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/eaa;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v1

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000o()Ljava/lang/String;

    move-result-object v3

    if-nez v3, :cond_c

    new-instance p1, Ljava/util/LinkedHashMap;

    invoke-direct {p1, v2}, Ljava/util/LinkedHashMap;-><init>(I)V

    invoke-virtual {p1, v0, v1}, Ljava/util/AbstractMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-object p1

    :cond_c
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/eaa;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v2

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000o()Ljava/lang/String;

    move-result-object v4

    if-nez v4, :cond_d

    new-instance p1, Ljava/util/LinkedHashMap;

    const/4 p2, 0x4

    invoke-direct {p1, p2}, Ljava/util/LinkedHashMap;-><init>(I)V

    invoke-virtual {p1, v0, v1}, Ljava/util/AbstractMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {p1, v3, v2}, Ljava/util/AbstractMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-object p1

    :cond_d
    new-instance v5, Ljava/util/LinkedHashMap;

    invoke-direct {v5}, Ljava/util/LinkedHashMap;-><init>()V

    invoke-virtual {v5, v0, v1}, Ljava/util/AbstractMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v5, v3, v2}, Ljava/util/AbstractMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_e
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/eaa;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v0

    invoke-virtual {v5, v4, v0}, Ljava/util/AbstractMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000o()Ljava/lang/String;

    move-result-object v4

    if-nez v4, :cond_e

    return-object v5

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_0
        :pswitch_b
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
    .end packed-switch
.end method

.method public final OooO0o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u3a;)Ljava/lang/Object;
    .locals 2

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0OoOo0()I

    move-result v0

    const/4 v1, 0x1

    if-eq v0, v1, :cond_2

    const/4 v1, 0x3

    if-eq v0, v1, :cond_2

    const/4 v1, 0x0

    packed-switch v0, :pswitch_data_0

    const-class p3, Ljava/lang/Object;

    invoke-virtual {p2, p3, p1}, Llyiahf/vczjk/v72;->o000000o(Ljava/lang/Class;Llyiahf/vczjk/eb4;)V

    throw v1

    :pswitch_0
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o000OOo()Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :pswitch_1
    return-object v1

    :pswitch_2
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    return-object p1

    :pswitch_3
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object p1

    :pswitch_4
    sget-object p3, Llyiahf/vczjk/w72;->OooOOO0:Llyiahf/vczjk/w72;

    invoke-virtual {p2, p3}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result p2

    if-eqz p2, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o00oO0o()Ljava/math/BigDecimal;

    move-result-object p1

    return-object p1

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o00000oo()Ljava/lang/Number;

    move-result-object p1

    return-object p1

    :pswitch_5
    sget-object p3, Llyiahf/vczjk/w72;->OooOOO:Llyiahf/vczjk/w72;

    invoke-virtual {p2, p3}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result p2

    if-eqz p2, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->OooOoOO()Ljava/math/BigInteger;

    move-result-object p1

    return-object p1

    :cond_1
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o00000oo()Ljava/lang/Number;

    move-result-object p1

    return-object p1

    :pswitch_6
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    move-result-object p1

    return-object p1

    :cond_2
    :pswitch_7
    invoke-virtual {p3, p2, p1}, Llyiahf/vczjk/u3a;->OooO0O0(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :pswitch_data_0
    .packed-switch 0x5
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

.method public final OooO0o0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    iget-boolean v0, p0, Llyiahf/vczjk/eaa;->_nonMerging:Z

    if-eqz v0, :cond_0

    invoke-virtual {p0, p2, p1}, Llyiahf/vczjk/eaa;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0OoOo0()I

    move-result v0

    const/4 v1, 0x1

    if-eq v0, v1, :cond_4

    const/4 v1, 0x2

    if-eq v0, v1, :cond_5

    const/4 v1, 0x3

    if-eq v0, v1, :cond_1

    const/4 v1, 0x4

    if-eq v0, v1, :cond_5

    const/4 v1, 0x5

    if-eq v0, v1, :cond_6

    goto :goto_2

    :cond_1
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/gc4;->OooOOo0:Llyiahf/vczjk/gc4;

    if-ne v0, v1, :cond_2

    goto :goto_0

    :cond_2
    instance-of v0, p3, Ljava/util/Collection;

    if-eqz v0, :cond_a

    move-object v0, p3

    check-cast v0, Ljava/util/Collection;

    :cond_3
    invoke-virtual {p0, p2, p1}, Llyiahf/vczjk/eaa;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/gc4;->OooOOo0:Llyiahf/vczjk/gc4;

    if-ne v1, v2, :cond_3

    return-object p3

    :cond_4
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/gc4;->OooOOOO:Llyiahf/vczjk/gc4;

    if-ne v0, v1, :cond_6

    :cond_5
    :goto_0
    return-object p3

    :cond_6
    instance-of v0, p3, Ljava/util/Map;

    if-eqz v0, :cond_a

    move-object v0, p3

    check-cast v0, Ljava/util/Map;

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->OoooOoo()Ljava/lang/String;

    move-result-object v1

    :cond_7
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    invoke-interface {v0, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    if-eqz v2, :cond_8

    invoke-virtual {p0, p1, p2, v2}, Llyiahf/vczjk/eaa;->OooO0o0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    goto :goto_1

    :cond_8
    invoke-virtual {p0, p2, p1}, Llyiahf/vczjk/eaa;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v3

    :goto_1
    if-eq v3, v2, :cond_9

    invoke-interface {v0, v1, v3}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_9
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000o()Ljava/lang/String;

    move-result-object v1

    if-nez v1, :cond_7

    return-object p3

    :cond_a
    :goto_2
    invoke-virtual {p0, p2, p1}, Llyiahf/vczjk/eaa;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final OooOOOO(Llyiahf/vczjk/t72;)Ljava/lang/Boolean;
    .locals 0

    iget-boolean p1, p0, Llyiahf/vczjk/eaa;->_nonMerging:Z

    if-eqz p1, :cond_0

    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    return-object p1

    :cond_0
    const/4 p1, 0x0

    return-object p1
.end method
