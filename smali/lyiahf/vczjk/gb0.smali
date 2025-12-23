.class public Llyiahf/vczjk/gb0;
.super Llyiahf/vczjk/nb7;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field public transient OooOOO:Ljava/lang/reflect/Method;

.field public transient OooOOOO:Ljava/lang/reflect/Field;

.field public transient OooOOOo:Llyiahf/vczjk/gb7;

.field public final transient OooOOo0:Ljava/util/HashMap;

.field protected final _cfgSerializationType:Llyiahf/vczjk/x64;

.field protected final _declaredType:Llyiahf/vczjk/x64;

.field protected final _includeInViews:[Ljava/lang/Class;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "[",
            "Ljava/lang/Class<",
            "*>;"
        }
    .end annotation
.end field

.field protected final _member:Llyiahf/vczjk/pm;

.field protected final _name:Llyiahf/vczjk/ng8;

.field protected _nonTrivialBaseType:Llyiahf/vczjk/x64;

.field protected _nullSerializer:Llyiahf/vczjk/zb4;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/zb4;"
        }
    .end annotation
.end field

.field protected _serializer:Llyiahf/vczjk/zb4;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/zb4;"
        }
    .end annotation
.end field

.field protected final _suppressNulls:Z

.field protected final _suppressableValue:Ljava/lang/Object;

.field protected _typeSerializer:Llyiahf/vczjk/d5a;

.field protected final _wrapperName:Llyiahf/vczjk/xa7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/eb0;Llyiahf/vczjk/pm;Llyiahf/vczjk/lo;Llyiahf/vczjk/x64;Llyiahf/vczjk/zb4;Llyiahf/vczjk/e5a;Llyiahf/vczjk/x64;ZLjava/lang/Object;[Ljava/lang/Class;)V
    .locals 1

    invoke-virtual {p1}, Llyiahf/vczjk/eb0;->OooO0O0()Llyiahf/vczjk/wa7;

    move-result-object p3

    invoke-direct {p0, p3}, Llyiahf/vczjk/lh1;-><init>(Llyiahf/vczjk/wa7;)V

    iput-object p2, p0, Llyiahf/vczjk/gb0;->_member:Llyiahf/vczjk/pm;

    new-instance p3, Llyiahf/vczjk/ng8;

    invoke-interface {p1}, Llyiahf/vczjk/yt5;->getName()Ljava/lang/String;

    move-result-object v0

    invoke-direct {p3, v0}, Llyiahf/vczjk/ng8;-><init>(Ljava/lang/String;)V

    iput-object p3, p0, Llyiahf/vczjk/gb0;->_name:Llyiahf/vczjk/ng8;

    invoke-virtual {p1}, Llyiahf/vczjk/eb0;->OooOOoo()Llyiahf/vczjk/xa7;

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/gb0;->_wrapperName:Llyiahf/vczjk/xa7;

    iput-object p4, p0, Llyiahf/vczjk/gb0;->_declaredType:Llyiahf/vczjk/x64;

    iput-object p5, p0, Llyiahf/vczjk/gb0;->_serializer:Llyiahf/vczjk/zb4;

    if-nez p5, :cond_0

    sget-object p3, Llyiahf/vczjk/cb7;->OooO00o:Llyiahf/vczjk/cb7;

    goto :goto_0

    :cond_0
    move-object p3, p1

    :goto_0
    iput-object p3, p0, Llyiahf/vczjk/gb0;->OooOOOo:Llyiahf/vczjk/gb7;

    iput-object p6, p0, Llyiahf/vczjk/gb0;->_typeSerializer:Llyiahf/vczjk/d5a;

    iput-object p7, p0, Llyiahf/vczjk/gb0;->_cfgSerializationType:Llyiahf/vczjk/x64;

    instance-of p3, p2, Llyiahf/vczjk/mm;

    if-eqz p3, :cond_1

    iput-object p1, p0, Llyiahf/vczjk/gb0;->OooOOO:Ljava/lang/reflect/Method;

    check-cast p2, Llyiahf/vczjk/mm;

    iget-object p2, p2, Llyiahf/vczjk/mm;->OooOo0o:Ljava/lang/reflect/Field;

    iput-object p2, p0, Llyiahf/vczjk/gb0;->OooOOOO:Ljava/lang/reflect/Field;

    goto :goto_1

    :cond_1
    instance-of p3, p2, Llyiahf/vczjk/rm;

    if-eqz p3, :cond_2

    check-cast p2, Llyiahf/vczjk/rm;

    iget-object p2, p2, Llyiahf/vczjk/rm;->OooOo0o:Ljava/lang/reflect/Method;

    iput-object p2, p0, Llyiahf/vczjk/gb0;->OooOOO:Ljava/lang/reflect/Method;

    iput-object p1, p0, Llyiahf/vczjk/gb0;->OooOOOO:Ljava/lang/reflect/Field;

    goto :goto_1

    :cond_2
    iput-object p1, p0, Llyiahf/vczjk/gb0;->OooOOO:Ljava/lang/reflect/Method;

    iput-object p1, p0, Llyiahf/vczjk/gb0;->OooOOOO:Ljava/lang/reflect/Field;

    :goto_1
    iput-boolean p8, p0, Llyiahf/vczjk/gb0;->_suppressNulls:Z

    iput-object p9, p0, Llyiahf/vczjk/gb0;->_suppressableValue:Ljava/lang/Object;

    iput-object p1, p0, Llyiahf/vczjk/gb0;->_nullSerializer:Llyiahf/vczjk/zb4;

    iput-object p10, p0, Llyiahf/vczjk/gb0;->_includeInViews:[Ljava/lang/Class;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/gb0;)V
    .locals 1

    iget-object v0, p1, Llyiahf/vczjk/gb0;->_name:Llyiahf/vczjk/ng8;

    invoke-direct {p0, p1, v0}, Llyiahf/vczjk/gb0;-><init>(Llyiahf/vczjk/gb0;Llyiahf/vczjk/ng8;)V

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/gb0;Llyiahf/vczjk/ng8;)V
    .locals 1

    invoke-direct {p0, p1}, Llyiahf/vczjk/lh1;-><init>(Llyiahf/vczjk/lh1;)V

    iput-object p2, p0, Llyiahf/vczjk/gb0;->_name:Llyiahf/vczjk/ng8;

    iget-object p2, p1, Llyiahf/vczjk/gb0;->_wrapperName:Llyiahf/vczjk/xa7;

    iput-object p2, p0, Llyiahf/vczjk/gb0;->_wrapperName:Llyiahf/vczjk/xa7;

    iget-object p2, p1, Llyiahf/vczjk/gb0;->_member:Llyiahf/vczjk/pm;

    iput-object p2, p0, Llyiahf/vczjk/gb0;->_member:Llyiahf/vczjk/pm;

    iget-object p2, p1, Llyiahf/vczjk/gb0;->_declaredType:Llyiahf/vczjk/x64;

    iput-object p2, p0, Llyiahf/vczjk/gb0;->_declaredType:Llyiahf/vczjk/x64;

    iget-object p2, p1, Llyiahf/vczjk/gb0;->OooOOO:Ljava/lang/reflect/Method;

    iput-object p2, p0, Llyiahf/vczjk/gb0;->OooOOO:Ljava/lang/reflect/Method;

    iget-object p2, p1, Llyiahf/vczjk/gb0;->OooOOOO:Ljava/lang/reflect/Field;

    iput-object p2, p0, Llyiahf/vczjk/gb0;->OooOOOO:Ljava/lang/reflect/Field;

    iget-object p2, p1, Llyiahf/vczjk/gb0;->_serializer:Llyiahf/vczjk/zb4;

    iput-object p2, p0, Llyiahf/vczjk/gb0;->_serializer:Llyiahf/vczjk/zb4;

    iget-object p2, p1, Llyiahf/vczjk/gb0;->_nullSerializer:Llyiahf/vczjk/zb4;

    iput-object p2, p0, Llyiahf/vczjk/gb0;->_nullSerializer:Llyiahf/vczjk/zb4;

    iget-object p2, p1, Llyiahf/vczjk/gb0;->OooOOo0:Ljava/util/HashMap;

    if-eqz p2, :cond_0

    new-instance p2, Ljava/util/HashMap;

    iget-object v0, p1, Llyiahf/vczjk/gb0;->OooOOo0:Ljava/util/HashMap;

    invoke-direct {p2, v0}, Ljava/util/HashMap;-><init>(Ljava/util/Map;)V

    iput-object p2, p0, Llyiahf/vczjk/gb0;->OooOOo0:Ljava/util/HashMap;

    :cond_0
    iget-object p2, p1, Llyiahf/vczjk/gb0;->_cfgSerializationType:Llyiahf/vczjk/x64;

    iput-object p2, p0, Llyiahf/vczjk/gb0;->_cfgSerializationType:Llyiahf/vczjk/x64;

    iget-object p2, p1, Llyiahf/vczjk/gb0;->OooOOOo:Llyiahf/vczjk/gb7;

    iput-object p2, p0, Llyiahf/vczjk/gb0;->OooOOOo:Llyiahf/vczjk/gb7;

    iget-boolean p2, p1, Llyiahf/vczjk/gb0;->_suppressNulls:Z

    iput-boolean p2, p0, Llyiahf/vczjk/gb0;->_suppressNulls:Z

    iget-object p2, p1, Llyiahf/vczjk/gb0;->_suppressableValue:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/gb0;->_suppressableValue:Ljava/lang/Object;

    iget-object p2, p1, Llyiahf/vczjk/gb0;->_includeInViews:[Ljava/lang/Class;

    iput-object p2, p0, Llyiahf/vczjk/gb0;->_includeInViews:[Ljava/lang/Class;

    iget-object p2, p1, Llyiahf/vczjk/gb0;->_typeSerializer:Llyiahf/vczjk/d5a;

    iput-object p2, p0, Llyiahf/vczjk/gb0;->_typeSerializer:Llyiahf/vczjk/d5a;

    iget-object p1, p1, Llyiahf/vczjk/gb0;->_nonTrivialBaseType:Llyiahf/vczjk/x64;

    iput-object p1, p0, Llyiahf/vczjk/gb0;->_nonTrivialBaseType:Llyiahf/vczjk/x64;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/gb0;Llyiahf/vczjk/xa7;)V
    .locals 1

    invoke-direct {p0, p1}, Llyiahf/vczjk/lh1;-><init>(Llyiahf/vczjk/lh1;)V

    new-instance v0, Llyiahf/vczjk/ng8;

    invoke-virtual {p2}, Llyiahf/vczjk/xa7;->OooO0OO()Ljava/lang/String;

    move-result-object p2

    invoke-direct {v0, p2}, Llyiahf/vczjk/ng8;-><init>(Ljava/lang/String;)V

    iput-object v0, p0, Llyiahf/vczjk/gb0;->_name:Llyiahf/vczjk/ng8;

    iget-object p2, p1, Llyiahf/vczjk/gb0;->_wrapperName:Llyiahf/vczjk/xa7;

    iput-object p2, p0, Llyiahf/vczjk/gb0;->_wrapperName:Llyiahf/vczjk/xa7;

    iget-object p2, p1, Llyiahf/vczjk/gb0;->_declaredType:Llyiahf/vczjk/x64;

    iput-object p2, p0, Llyiahf/vczjk/gb0;->_declaredType:Llyiahf/vczjk/x64;

    iget-object p2, p1, Llyiahf/vczjk/gb0;->_member:Llyiahf/vczjk/pm;

    iput-object p2, p0, Llyiahf/vczjk/gb0;->_member:Llyiahf/vczjk/pm;

    iget-object p2, p1, Llyiahf/vczjk/gb0;->OooOOO:Ljava/lang/reflect/Method;

    iput-object p2, p0, Llyiahf/vczjk/gb0;->OooOOO:Ljava/lang/reflect/Method;

    iget-object p2, p1, Llyiahf/vczjk/gb0;->OooOOOO:Ljava/lang/reflect/Field;

    iput-object p2, p0, Llyiahf/vczjk/gb0;->OooOOOO:Ljava/lang/reflect/Field;

    iget-object p2, p1, Llyiahf/vczjk/gb0;->_serializer:Llyiahf/vczjk/zb4;

    iput-object p2, p0, Llyiahf/vczjk/gb0;->_serializer:Llyiahf/vczjk/zb4;

    iget-object p2, p1, Llyiahf/vczjk/gb0;->_nullSerializer:Llyiahf/vczjk/zb4;

    iput-object p2, p0, Llyiahf/vczjk/gb0;->_nullSerializer:Llyiahf/vczjk/zb4;

    iget-object p2, p1, Llyiahf/vczjk/gb0;->OooOOo0:Ljava/util/HashMap;

    if-eqz p2, :cond_0

    new-instance p2, Ljava/util/HashMap;

    iget-object v0, p1, Llyiahf/vczjk/gb0;->OooOOo0:Ljava/util/HashMap;

    invoke-direct {p2, v0}, Ljava/util/HashMap;-><init>(Ljava/util/Map;)V

    iput-object p2, p0, Llyiahf/vczjk/gb0;->OooOOo0:Ljava/util/HashMap;

    :cond_0
    iget-object p2, p1, Llyiahf/vczjk/gb0;->_cfgSerializationType:Llyiahf/vczjk/x64;

    iput-object p2, p0, Llyiahf/vczjk/gb0;->_cfgSerializationType:Llyiahf/vczjk/x64;

    iget-object p2, p1, Llyiahf/vczjk/gb0;->OooOOOo:Llyiahf/vczjk/gb7;

    iput-object p2, p0, Llyiahf/vczjk/gb0;->OooOOOo:Llyiahf/vczjk/gb7;

    iget-boolean p2, p1, Llyiahf/vczjk/gb0;->_suppressNulls:Z

    iput-boolean p2, p0, Llyiahf/vczjk/gb0;->_suppressNulls:Z

    iget-object p2, p1, Llyiahf/vczjk/gb0;->_suppressableValue:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/gb0;->_suppressableValue:Ljava/lang/Object;

    iget-object p2, p1, Llyiahf/vczjk/gb0;->_includeInViews:[Ljava/lang/Class;

    iput-object p2, p0, Llyiahf/vczjk/gb0;->_includeInViews:[Ljava/lang/Class;

    iget-object p2, p1, Llyiahf/vczjk/gb0;->_typeSerializer:Llyiahf/vczjk/d5a;

    iput-object p2, p0, Llyiahf/vczjk/gb0;->_typeSerializer:Llyiahf/vczjk/d5a;

    iget-object p1, p1, Llyiahf/vczjk/gb0;->_nonTrivialBaseType:Llyiahf/vczjk/x64;

    iput-object p1, p0, Llyiahf/vczjk/gb0;->_nonTrivialBaseType:Llyiahf/vczjk/x64;

    return-void
.end method


# virtual methods
.method public OooO(Llyiahf/vczjk/zb4;)V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/gb0;->_serializer:Llyiahf/vczjk/zb4;

    if-eqz v0, :cond_1

    if-ne v0, p1, :cond_0

    goto :goto_0

    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    iget-object v1, p0, Llyiahf/vczjk/gb0;->_serializer:Llyiahf/vczjk/zb4;

    invoke-static {v1}, Llyiahf/vczjk/vy0;->OooO0o0(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v1

    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooO0o0(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    const-string v2, "Cannot override _serializer: had a "

    const-string v3, ", trying to set to "

    invoke-static {v2, v1, v3, p1}, Llyiahf/vczjk/ii5;->OooO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_1
    :goto_0
    iput-object p1, p0, Llyiahf/vczjk/gb0;->_serializer:Llyiahf/vczjk/zb4;

    return-void
.end method

.method public final OooO00o()Llyiahf/vczjk/pm;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/gb0;->_member:Llyiahf/vczjk/pm;

    return-object v0
.end method

.method public OooO0o(Llyiahf/vczjk/gb7;Ljava/lang/Class;Llyiahf/vczjk/tg8;)Llyiahf/vczjk/zb4;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/gb0;->_nonTrivialBaseType:Llyiahf/vczjk/x64;

    if-eqz v0, :cond_0

    invoke-virtual {p3, p2, v0}, Llyiahf/vczjk/tg8;->ooOO(Ljava/lang/Class;Llyiahf/vczjk/x64;)Llyiahf/vczjk/x64;

    move-result-object p2

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {p3, p2, p0}, Llyiahf/vczjk/tg8;->o00oO0O(Llyiahf/vczjk/x64;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object p3

    new-instance v0, Llyiahf/vczjk/a27;

    invoke-virtual {p2}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object p2

    invoke-virtual {p1, p2, p3}, Llyiahf/vczjk/gb7;->OooO0O0(Ljava/lang/Class;Llyiahf/vczjk/zb4;)Llyiahf/vczjk/gb7;

    move-result-object p2

    const/16 v1, 0x1a

    const/4 v2, 0x0

    invoke-direct {v0, v1, p3, p2, v2}, Llyiahf/vczjk/a27;-><init>(ILjava/lang/Object;Ljava/lang/Object;Z)V

    goto :goto_0

    :cond_0
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {p3, p2, p0}, Llyiahf/vczjk/tg8;->o00oO0o(Ljava/lang/Class;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object p3

    new-instance v0, Llyiahf/vczjk/a27;

    invoke-virtual {p1, p2, p3}, Llyiahf/vczjk/gb7;->OooO0O0(Ljava/lang/Class;Llyiahf/vczjk/zb4;)Llyiahf/vczjk/gb7;

    move-result-object p2

    const/16 v1, 0x1a

    const/4 v2, 0x0

    invoke-direct {v0, v1, p3, p2, v2}, Llyiahf/vczjk/a27;-><init>(ILjava/lang/Object;Ljava/lang/Object;Z)V

    :goto_0
    iget-object p2, v0, Llyiahf/vczjk/a27;->OooOOOO:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/gb7;

    if-eq p1, p2, :cond_1

    iput-object p2, p0, Llyiahf/vczjk/gb0;->OooOOOo:Llyiahf/vczjk/gb7;

    :cond_1
    iget-object p1, v0, Llyiahf/vczjk/a27;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/zb4;

    return-object p1
.end method

.method public final OooO0oO(Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Llyiahf/vczjk/zb4;)Z
    .locals 2

    invoke-virtual {p3}, Llyiahf/vczjk/zb4;->OooO()Z

    move-result v0

    if-nez v0, :cond_4

    sget-object v0, Llyiahf/vczjk/ig8;->OooOOOo:Llyiahf/vczjk/ig8;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/tg8;->o0000Ooo(Llyiahf/vczjk/ig8;)Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_1

    instance-of p1, p3, Llyiahf/vczjk/ib0;

    if-nez p1, :cond_0

    goto :goto_0

    :cond_0
    iget-object p1, p0, Llyiahf/vczjk/gb0;->_declaredType:Llyiahf/vczjk/x64;

    const-string p3, "Direct self-reference leading to cycle"

    invoke-virtual {p2, p1, p3}, Llyiahf/vczjk/tg8;->OoooOOO(Llyiahf/vczjk/x64;Ljava/lang/String;)Ljava/lang/Object;

    throw v1

    :cond_1
    sget-object p3, Llyiahf/vczjk/ig8;->OooOOoo:Llyiahf/vczjk/ig8;

    invoke-virtual {p2, p3}, Llyiahf/vczjk/tg8;->o0000Ooo(Llyiahf/vczjk/ig8;)Z

    move-result p3

    if-eqz p3, :cond_4

    iget-object p3, p0, Llyiahf/vczjk/gb0;->_nullSerializer:Llyiahf/vczjk/zb4;

    if-eqz p3, :cond_3

    invoke-virtual {p1}, Llyiahf/vczjk/u94;->OooOoOO()Llyiahf/vczjk/yc4;

    move-result-object p3

    invoke-virtual {p3}, Llyiahf/vczjk/b23;->OooO0oO()Z

    move-result p3

    if-nez p3, :cond_2

    iget-object p3, p0, Llyiahf/vczjk/gb0;->_name:Llyiahf/vczjk/ng8;

    invoke-virtual {p1, p3}, Llyiahf/vczjk/u94;->o00000oO(Llyiahf/vczjk/fg8;)V

    :cond_2
    iget-object p3, p0, Llyiahf/vczjk/gb0;->_nullSerializer:Llyiahf/vczjk/zb4;

    invoke-virtual {p3, v1, p1, p2}, Llyiahf/vczjk/zb4;->OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    :cond_3
    const/4 p1, 0x1

    return p1

    :cond_4
    :goto_0
    const/4 p1, 0x0

    return p1
.end method

.method public OooO0oo(Llyiahf/vczjk/zb4;)V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/gb0;->_nullSerializer:Llyiahf/vczjk/zb4;

    if-eqz v0, :cond_1

    if-ne v0, p1, :cond_0

    goto :goto_0

    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    iget-object v1, p0, Llyiahf/vczjk/gb0;->_nullSerializer:Llyiahf/vczjk/zb4;

    invoke-static {v1}, Llyiahf/vczjk/vy0;->OooO0o0(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v1

    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooO0o0(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    const-string v2, "Cannot override _nullSerializer: had a "

    const-string v3, ", trying to set to "

    invoke-static {v2, v1, v3, p1}, Llyiahf/vczjk/ii5;->OooO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_1
    :goto_0
    iput-object p1, p0, Llyiahf/vczjk/gb0;->_nullSerializer:Llyiahf/vczjk/zb4;

    return-void
.end method

.method public OooOO0(Llyiahf/vczjk/wt5;)Llyiahf/vczjk/gb0;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/gb0;->_name:Llyiahf/vczjk/ng8;

    invoke-virtual {v0}, Llyiahf/vczjk/ng8;->OooO0oO()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/wt5;->OooO00o(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/gb0;->_name:Llyiahf/vczjk/ng8;

    invoke-virtual {v0}, Llyiahf/vczjk/ng8;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    return-object p0

    :cond_0
    invoke-static {p1}, Llyiahf/vczjk/xa7;->OooO00o(Ljava/lang/String;)Llyiahf/vczjk/xa7;

    move-result-object p1

    new-instance v0, Llyiahf/vczjk/gb0;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/gb0;-><init>(Llyiahf/vczjk/gb0;Llyiahf/vczjk/xa7;)V

    return-object v0
.end method

.method public OooOO0O(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/gb0;->OooOOO:Ljava/lang/reflect/Method;

    const/4 v1, 0x0

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/gb0;->OooOOOO:Ljava/lang/reflect/Field;

    invoke-virtual {v0, p1}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    goto :goto_0

    :cond_0
    invoke-virtual {v0, p1, v1}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    :goto_0
    if-nez v0, :cond_2

    iget-object p1, p0, Llyiahf/vczjk/gb0;->_nullSerializer:Llyiahf/vczjk/zb4;

    if-eqz p1, :cond_1

    invoke-virtual {p1, v1, p2, p3}, Llyiahf/vczjk/zb4;->OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    return-void

    :cond_1
    invoke-virtual {p2}, Llyiahf/vczjk/u94;->o00000oo()V

    return-void

    :cond_2
    iget-object v1, p0, Llyiahf/vczjk/gb0;->_serializer:Llyiahf/vczjk/zb4;

    if-nez v1, :cond_4

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    iget-object v2, p0, Llyiahf/vczjk/gb0;->OooOOOo:Llyiahf/vczjk/gb7;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/gb7;->OooO0OO(Ljava/lang/Class;)Llyiahf/vczjk/zb4;

    move-result-object v3

    if-nez v3, :cond_3

    invoke-virtual {p0, v2, v1, p3}, Llyiahf/vczjk/gb0;->OooO0o(Llyiahf/vczjk/gb7;Ljava/lang/Class;Llyiahf/vczjk/tg8;)Llyiahf/vczjk/zb4;

    move-result-object v1

    goto :goto_1

    :cond_3
    move-object v1, v3

    :cond_4
    :goto_1
    iget-object v2, p0, Llyiahf/vczjk/gb0;->_suppressableValue:Ljava/lang/Object;

    if-eqz v2, :cond_6

    sget-object v3, Llyiahf/vczjk/ea4;->OooOOOO:Llyiahf/vczjk/ea4;

    if-ne v3, v2, :cond_5

    invoke-virtual {v1, p3, v0}, Llyiahf/vczjk/zb4;->OooO0Oo(Llyiahf/vczjk/tg8;Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_6

    invoke-virtual {p0, p2, p3}, Llyiahf/vczjk/gb0;->OooOOO0(Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    return-void

    :cond_5
    invoke-virtual {v2, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_6

    invoke-virtual {p0, p2, p3}, Llyiahf/vczjk/gb0;->OooOOO0(Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    return-void

    :cond_6
    if-ne v0, p1, :cond_7

    invoke-virtual {p0, p2, p3, v1}, Llyiahf/vczjk/gb0;->OooO0oO(Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Llyiahf/vczjk/zb4;)Z

    move-result p1

    if-eqz p1, :cond_7

    return-void

    :cond_7
    iget-object p1, p0, Llyiahf/vczjk/gb0;->_typeSerializer:Llyiahf/vczjk/d5a;

    if-nez p1, :cond_8

    invoke-virtual {v1, v0, p2, p3}, Llyiahf/vczjk/zb4;->OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    return-void

    :cond_8
    invoke-virtual {v1, v0, p2, p3, p1}, Llyiahf/vczjk/zb4;->OooO0oO(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Llyiahf/vczjk/d5a;)V

    return-void
.end method

.method public OooOO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/gb0;->OooOOO:Ljava/lang/reflect/Method;

    const/4 v1, 0x0

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/gb0;->OooOOOO:Ljava/lang/reflect/Field;

    invoke-virtual {v0, p1}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    goto :goto_0

    :cond_0
    invoke-virtual {v0, p1, v1}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    :goto_0
    if-nez v0, :cond_1

    iget-object p1, p0, Llyiahf/vczjk/gb0;->_nullSerializer:Llyiahf/vczjk/zb4;

    if-eqz p1, :cond_6

    iget-object p1, p0, Llyiahf/vczjk/gb0;->_name:Llyiahf/vczjk/ng8;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/u94;->o00000oO(Llyiahf/vczjk/fg8;)V

    iget-object p1, p0, Llyiahf/vczjk/gb0;->_nullSerializer:Llyiahf/vczjk/zb4;

    invoke-virtual {p1, v1, p2, p3}, Llyiahf/vczjk/zb4;->OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    return-void

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/gb0;->_serializer:Llyiahf/vczjk/zb4;

    if-nez v1, :cond_3

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    iget-object v2, p0, Llyiahf/vczjk/gb0;->OooOOOo:Llyiahf/vczjk/gb7;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/gb7;->OooO0OO(Ljava/lang/Class;)Llyiahf/vczjk/zb4;

    move-result-object v3

    if-nez v3, :cond_2

    invoke-virtual {p0, v2, v1, p3}, Llyiahf/vczjk/gb0;->OooO0o(Llyiahf/vczjk/gb7;Ljava/lang/Class;Llyiahf/vczjk/tg8;)Llyiahf/vczjk/zb4;

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
    if-ne v0, p1, :cond_7

    invoke-virtual {p0, p2, p3, v1}, Llyiahf/vczjk/gb0;->OooO0oO(Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Llyiahf/vczjk/zb4;)Z

    move-result p1

    if-eqz p1, :cond_7

    :cond_6
    :goto_2
    return-void

    :cond_7
    iget-object p1, p0, Llyiahf/vczjk/gb0;->_name:Llyiahf/vczjk/ng8;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/u94;->o00000oO(Llyiahf/vczjk/fg8;)V

    iget-object p1, p0, Llyiahf/vczjk/gb0;->_typeSerializer:Llyiahf/vczjk/d5a;

    if-nez p1, :cond_8

    invoke-virtual {v1, v0, p2, p3}, Llyiahf/vczjk/zb4;->OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    return-void

    :cond_8
    invoke-virtual {v1, v0, p2, p3, p1}, Llyiahf/vczjk/zb4;->OooO0oO(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Llyiahf/vczjk/d5a;)V

    return-void
.end method

.method public final OooOOO0(Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/gb0;->_nullSerializer:Llyiahf/vczjk/zb4;

    if-eqz v0, :cond_0

    const/4 v1, 0x0

    invoke-virtual {v0, v1, p1, p2}, Llyiahf/vczjk/zb4;->OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    return-void

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/u94;->o00000oo()V

    return-void
.end method

.method public final getFullName()Llyiahf/vczjk/xa7;
    .locals 3

    new-instance v0, Llyiahf/vczjk/xa7;

    iget-object v1, p0, Llyiahf/vczjk/gb0;->_name:Llyiahf/vczjk/ng8;

    invoke-virtual {v1}, Llyiahf/vczjk/ng8;->OooO0oO()Ljava/lang/String;

    move-result-object v1

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/xa7;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    return-object v0
.end method

.method public final getName()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/gb0;->_name:Llyiahf/vczjk/ng8;

    invoke-virtual {v0}, Llyiahf/vczjk/ng8;->OooO0oO()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final getType()Llyiahf/vczjk/x64;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/gb0;->_declaredType:Llyiahf/vczjk/x64;

    return-object v0
.end method

.method public readResolve()Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/gb0;->_member:Llyiahf/vczjk/pm;

    instance-of v1, v0, Llyiahf/vczjk/mm;

    const/4 v2, 0x0

    if-eqz v1, :cond_0

    iput-object v2, p0, Llyiahf/vczjk/gb0;->OooOOO:Ljava/lang/reflect/Method;

    invoke-virtual {v0}, Llyiahf/vczjk/pm;->o0ooOO0()Ljava/lang/reflect/Member;

    move-result-object v0

    check-cast v0, Ljava/lang/reflect/Field;

    iput-object v0, p0, Llyiahf/vczjk/gb0;->OooOOOO:Ljava/lang/reflect/Field;

    goto :goto_0

    :cond_0
    instance-of v1, v0, Llyiahf/vczjk/rm;

    if-eqz v1, :cond_1

    invoke-virtual {v0}, Llyiahf/vczjk/pm;->o0ooOO0()Ljava/lang/reflect/Member;

    move-result-object v0

    check-cast v0, Ljava/lang/reflect/Method;

    iput-object v0, p0, Llyiahf/vczjk/gb0;->OooOOO:Ljava/lang/reflect/Method;

    iput-object v2, p0, Llyiahf/vczjk/gb0;->OooOOOO:Ljava/lang/reflect/Field;

    :cond_1
    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/gb0;->_serializer:Llyiahf/vczjk/zb4;

    if-nez v0, :cond_2

    sget-object v0, Llyiahf/vczjk/cb7;->OooO00o:Llyiahf/vczjk/cb7;

    iput-object v0, p0, Llyiahf/vczjk/gb0;->OooOOOo:Llyiahf/vczjk/gb7;

    :cond_2
    return-object p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    const/16 v0, 0x28

    const-string v1, "property \'"

    invoke-static {v0, v1}, Llyiahf/vczjk/ix8;->OooOOO0(ILjava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/gb0;->_name:Llyiahf/vczjk/ng8;

    invoke-virtual {v1}, Llyiahf/vczjk/ng8;->OooO0oO()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, "\' ("

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/gb0;->OooOOO:Ljava/lang/reflect/Method;

    const-string v2, "#"

    if-eqz v1, :cond_0

    const-string v1, "via method "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/gb0;->OooOOO:Ljava/lang/reflect/Method;

    invoke-virtual {v1}, Ljava/lang/reflect/Method;->getDeclaringClass()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/gb0;->OooOOO:Ljava/lang/reflect/Method;

    invoke-virtual {v1}, Ljava/lang/reflect/Method;->getName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto :goto_0

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/gb0;->OooOOOO:Ljava/lang/reflect/Field;

    if-eqz v1, :cond_1

    const-string v1, "field \""

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/gb0;->OooOOOO:Ljava/lang/reflect/Field;

    invoke-virtual {v1}, Ljava/lang/reflect/Field;->getDeclaringClass()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/gb0;->OooOOOO:Ljava/lang/reflect/Field;

    invoke-virtual {v1}, Ljava/lang/reflect/Field;->getName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto :goto_0

    :cond_1
    const-string v1, "virtual"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    :goto_0
    iget-object v1, p0, Llyiahf/vczjk/gb0;->_serializer:Llyiahf/vczjk/zb4;

    if-nez v1, :cond_2

    const-string v1, ", no static serializer"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto :goto_1

    :cond_2
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v1

    const-string v2, ", static serializer of type "

    invoke-virtual {v2, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    :goto_1
    const/16 v1, 0x29

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
