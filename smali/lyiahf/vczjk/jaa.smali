.class public final Llyiahf/vczjk/jaa;
.super Llyiahf/vczjk/gb0;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected final _nameTransformer:Llyiahf/vczjk/wt5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/gb0;Llyiahf/vczjk/wt5;)V
    .locals 0

    invoke-direct {p0, p1}, Llyiahf/vczjk/gb0;-><init>(Llyiahf/vczjk/gb0;)V

    iput-object p2, p0, Llyiahf/vczjk/jaa;->_nameTransformer:Llyiahf/vczjk/wt5;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/jaa;Llyiahf/vczjk/ut5;Llyiahf/vczjk/ng8;)V
    .locals 0

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/gb0;-><init>(Llyiahf/vczjk/gb0;Llyiahf/vczjk/ng8;)V

    iput-object p2, p0, Llyiahf/vczjk/jaa;->_nameTransformer:Llyiahf/vczjk/wt5;

    return-void
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/zb4;)V
    .locals 3

    if-eqz p1, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/jaa;->_nameTransformer:Llyiahf/vczjk/wt5;

    invoke-virtual {p1}, Llyiahf/vczjk/zb4;->OooO0o0()Z

    move-result v1

    if-eqz v1, :cond_0

    instance-of v1, p1, Llyiahf/vczjk/kaa;

    if-eqz v1, :cond_0

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/kaa;

    iget-object v1, v1, Llyiahf/vczjk/kaa;->_nameTransformer:Llyiahf/vczjk/wt5;

    new-instance v2, Llyiahf/vczjk/ut5;

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/ut5;-><init>(Llyiahf/vczjk/wt5;Llyiahf/vczjk/wt5;)V

    move-object v0, v2

    :cond_0
    invoke-virtual {p1, v0}, Llyiahf/vczjk/zb4;->OooO0oo(Llyiahf/vczjk/wt5;)Llyiahf/vczjk/zb4;

    move-result-object p1

    :cond_1
    invoke-super {p0, p1}, Llyiahf/vczjk/gb0;->OooO(Llyiahf/vczjk/zb4;)V

    return-void
.end method

.method public final OooO0o(Llyiahf/vczjk/gb7;Ljava/lang/Class;Llyiahf/vczjk/tg8;)Llyiahf/vczjk/zb4;
    .locals 2

    iget-object p1, p0, Llyiahf/vczjk/gb0;->_nonTrivialBaseType:Llyiahf/vczjk/x64;

    if-eqz p1, :cond_0

    invoke-virtual {p3, p2, p1}, Llyiahf/vczjk/tg8;->ooOO(Ljava/lang/Class;Llyiahf/vczjk/x64;)Llyiahf/vczjk/x64;

    move-result-object p1

    invoke-virtual {p3, p1, p0}, Llyiahf/vczjk/tg8;->o0OO00O(Llyiahf/vczjk/x64;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object p1

    goto :goto_0

    :cond_0
    invoke-virtual {p3, p2, p0}, Llyiahf/vczjk/tg8;->o0OOO0o(Ljava/lang/Class;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object p1

    :goto_0
    iget-object p3, p0, Llyiahf/vczjk/jaa;->_nameTransformer:Llyiahf/vczjk/wt5;

    invoke-virtual {p1}, Llyiahf/vczjk/zb4;->OooO0o0()Z

    move-result v0

    if-eqz v0, :cond_1

    instance-of v0, p1, Llyiahf/vczjk/kaa;

    if-eqz v0, :cond_1

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/kaa;

    iget-object v0, v0, Llyiahf/vczjk/kaa;->_nameTransformer:Llyiahf/vczjk/wt5;

    new-instance v1, Llyiahf/vczjk/ut5;

    invoke-direct {v1, p3, v0}, Llyiahf/vczjk/ut5;-><init>(Llyiahf/vczjk/wt5;Llyiahf/vczjk/wt5;)V

    move-object p3, v1

    :cond_1
    invoke-virtual {p1, p3}, Llyiahf/vczjk/zb4;->OooO0oo(Llyiahf/vczjk/wt5;)Llyiahf/vczjk/zb4;

    move-result-object p1

    iget-object p3, p0, Llyiahf/vczjk/gb0;->OooOOOo:Llyiahf/vczjk/gb7;

    invoke-virtual {p3, p2, p1}, Llyiahf/vczjk/gb7;->OooO0O0(Ljava/lang/Class;Llyiahf/vczjk/zb4;)Llyiahf/vczjk/gb7;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/gb0;->OooOOOo:Llyiahf/vczjk/gb7;

    return-object p1
.end method

.method public final OooOO0(Llyiahf/vczjk/wt5;)Llyiahf/vczjk/gb0;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/gb0;->_name:Llyiahf/vczjk/ng8;

    invoke-virtual {v0}, Llyiahf/vczjk/ng8;->OooO0oO()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/wt5;->OooO00o(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/jaa;->_nameTransformer:Llyiahf/vczjk/wt5;

    new-instance v2, Llyiahf/vczjk/ut5;

    invoke-direct {v2, p1, v1}, Llyiahf/vczjk/ut5;-><init>(Llyiahf/vczjk/wt5;Llyiahf/vczjk/wt5;)V

    new-instance p1, Llyiahf/vczjk/ng8;

    invoke-direct {p1, v0}, Llyiahf/vczjk/ng8;-><init>(Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/jaa;

    invoke-direct {v0, p0, v2, p1}, Llyiahf/vczjk/jaa;-><init>(Llyiahf/vczjk/jaa;Llyiahf/vczjk/ut5;Llyiahf/vczjk/ng8;)V

    return-object v0
.end method

.method public final OooOO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/gb0;->OooOOO:Ljava/lang/reflect/Method;

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/gb0;->OooOOOO:Ljava/lang/reflect/Field;

    invoke-virtual {v0, p1}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    goto :goto_0

    :cond_0
    const/4 v1, 0x0

    invoke-virtual {v0, p1, v1}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    :goto_0
    if-nez v0, :cond_1

    goto :goto_2

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/gb0;->_serializer:Llyiahf/vczjk/zb4;

    if-nez v1, :cond_3

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    iget-object v2, p0, Llyiahf/vczjk/gb0;->OooOOOo:Llyiahf/vczjk/gb7;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/gb7;->OooO0OO(Ljava/lang/Class;)Llyiahf/vczjk/zb4;

    move-result-object v3

    if-nez v3, :cond_2

    invoke-virtual {p0, v2, v1, p3}, Llyiahf/vczjk/jaa;->OooO0o(Llyiahf/vczjk/gb7;Ljava/lang/Class;Llyiahf/vczjk/tg8;)Llyiahf/vczjk/zb4;

    move-result-object v1

    goto :goto_1

    :cond_2
    move-object v1, v3

    :cond_3
    :goto_1
    iget-object v2, p0, Llyiahf/vczjk/gb0;->_suppressableValue:Ljava/lang/Object;

    if-eqz v2, :cond_5

    sget-object v3, Llyiahf/vczjk/ea4;->OooOOOO:Llyiahf/vczjk/ea4;

    if-ne v3, v2, :cond_4

    invoke-virtual {v1, p3, v0}, Llyiahf/vczjk/zb4;->OooO0Oo(Llyiahf/vczjk/tg8;Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_5

    goto :goto_2

    :cond_4
    invoke-virtual {v2, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_5

    goto :goto_2

    :cond_5
    if-ne v0, p1, :cond_6

    invoke-virtual {p0, p2, p3, v1}, Llyiahf/vczjk/gb0;->OooO0oO(Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Llyiahf/vczjk/zb4;)Z

    move-result p1

    if-eqz p1, :cond_6

    :goto_2
    return-void

    :cond_6
    invoke-virtual {v1}, Llyiahf/vczjk/zb4;->OooO0o0()Z

    move-result p1

    if-nez p1, :cond_7

    iget-object p1, p0, Llyiahf/vczjk/gb0;->_name:Llyiahf/vczjk/ng8;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/u94;->o00000oO(Llyiahf/vczjk/fg8;)V

    :cond_7
    iget-object p1, p0, Llyiahf/vczjk/gb0;->_typeSerializer:Llyiahf/vczjk/d5a;

    if-nez p1, :cond_8

    invoke-virtual {v1, v0, p2, p3}, Llyiahf/vczjk/zb4;->OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    return-void

    :cond_8
    invoke-virtual {v1, v0, p2, p3, p1}, Llyiahf/vczjk/zb4;->OooO0oO(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Llyiahf/vczjk/d5a;)V

    return-void
.end method
