.class public Llyiahf/vczjk/l94;
.super Llyiahf/vczjk/au9;
.source "SourceFile"


# static fields
.field public static final OooOOOO:I

.field public static final OooOOOo:I

.field public static final OooOOo:Llyiahf/vczjk/ng8;

.field public static final OooOOo0:I

.field private static final serialVersionUID:J = 0x2L


# instance fields
.field public final transient OooOOO:Llyiahf/vczjk/xl0;

.field public final transient OooOOO0:Llyiahf/vczjk/du0;

.field protected _characterEscapes:Llyiahf/vczjk/xt0;

.field protected _factoryFeatures:I

.field protected _generatorFeatures:I

.field protected _inputDecorator:Llyiahf/vczjk/h04;

.field protected _maximumNonEscapedChar:I

.field protected _objectCodec:Llyiahf/vczjk/l66;

.field protected _outputDecorator:Llyiahf/vczjk/hg6;

.field protected _parserFeatures:I

.field protected final _quoteChar:C

.field protected _rootValueSeparator:Llyiahf/vczjk/fg8;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    invoke-static {}, Llyiahf/vczjk/k94;->OooO00o()I

    move-result v0

    sput v0, Llyiahf/vczjk/l94;->OooOOOO:I

    invoke-static {}, Llyiahf/vczjk/cb4;->OooO00o()I

    move-result v0

    sput v0, Llyiahf/vczjk/l94;->OooOOOo:I

    invoke-static {}, Llyiahf/vczjk/t94;->OooO00o()I

    move-result v0

    sput v0, Llyiahf/vczjk/l94;->OooOOo0:I

    sget-object v0, Llyiahf/vczjk/j32;->OooOOO:Llyiahf/vczjk/ng8;

    sput-object v0, Llyiahf/vczjk/l94;->OooOOo:Llyiahf/vczjk/ng8;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/e76;)V
    .locals 4

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v0

    long-to-int v2, v0

    const/16 v3, 0x20

    ushr-long/2addr v0, v3

    long-to-int v0, v0

    add-int/2addr v2, v0

    or-int/lit8 v0, v2, 0x1

    new-instance v1, Llyiahf/vczjk/du0;

    invoke-direct {v1, v0}, Llyiahf/vczjk/du0;-><init>(I)V

    iput-object v1, p0, Llyiahf/vczjk/l94;->OooOOO0:Llyiahf/vczjk/du0;

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v0

    long-to-int v2, v0

    ushr-long/2addr v0, v3

    long-to-int v0, v0

    add-int/2addr v2, v0

    or-int/lit8 v0, v2, 0x1

    new-instance v1, Llyiahf/vczjk/xl0;

    invoke-direct {v1, v0}, Llyiahf/vczjk/xl0;-><init>(I)V

    iput-object v1, p0, Llyiahf/vczjk/l94;->OooOOO:Llyiahf/vczjk/xl0;

    sget v0, Llyiahf/vczjk/l94;->OooOOOO:I

    iput v0, p0, Llyiahf/vczjk/l94;->_factoryFeatures:I

    sget v0, Llyiahf/vczjk/l94;->OooOOOo:I

    iput v0, p0, Llyiahf/vczjk/l94;->_parserFeatures:I

    sget v0, Llyiahf/vczjk/l94;->OooOOo0:I

    iput v0, p0, Llyiahf/vczjk/l94;->_generatorFeatures:I

    sget-object v0, Llyiahf/vczjk/l94;->OooOOo:Llyiahf/vczjk/ng8;

    iput-object v0, p0, Llyiahf/vczjk/l94;->_rootValueSeparator:Llyiahf/vczjk/fg8;

    iput-object p1, p0, Llyiahf/vczjk/l94;->_objectCodec:Llyiahf/vczjk/l66;

    const/16 p1, 0x22

    iput-char p1, p0, Llyiahf/vczjk/l94;->_quoteChar:C

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/l94;Llyiahf/vczjk/l66;)V
    .locals 4

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v0

    long-to-int v2, v0

    const/16 v3, 0x20

    ushr-long/2addr v0, v3

    long-to-int v0, v0

    add-int/2addr v2, v0

    or-int/lit8 v0, v2, 0x1

    new-instance v1, Llyiahf/vczjk/du0;

    invoke-direct {v1, v0}, Llyiahf/vczjk/du0;-><init>(I)V

    iput-object v1, p0, Llyiahf/vczjk/l94;->OooOOO0:Llyiahf/vczjk/du0;

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v0

    long-to-int v2, v0

    ushr-long/2addr v0, v3

    long-to-int v0, v0

    add-int/2addr v2, v0

    or-int/lit8 v0, v2, 0x1

    new-instance v1, Llyiahf/vczjk/xl0;

    invoke-direct {v1, v0}, Llyiahf/vczjk/xl0;-><init>(I)V

    iput-object v1, p0, Llyiahf/vczjk/l94;->OooOOO:Llyiahf/vczjk/xl0;

    sget v0, Llyiahf/vczjk/l94;->OooOOOO:I

    iput v0, p0, Llyiahf/vczjk/l94;->_factoryFeatures:I

    sget v0, Llyiahf/vczjk/l94;->OooOOOo:I

    iput v0, p0, Llyiahf/vczjk/l94;->_parserFeatures:I

    sget v0, Llyiahf/vczjk/l94;->OooOOo0:I

    iput v0, p0, Llyiahf/vczjk/l94;->_generatorFeatures:I

    sget-object v0, Llyiahf/vczjk/l94;->OooOOo:Llyiahf/vczjk/ng8;

    iput-object v0, p0, Llyiahf/vczjk/l94;->_rootValueSeparator:Llyiahf/vczjk/fg8;

    iput-object p2, p0, Llyiahf/vczjk/l94;->_objectCodec:Llyiahf/vczjk/l66;

    iget p2, p1, Llyiahf/vczjk/l94;->_factoryFeatures:I

    iput p2, p0, Llyiahf/vczjk/l94;->_factoryFeatures:I

    iget p2, p1, Llyiahf/vczjk/l94;->_parserFeatures:I

    iput p2, p0, Llyiahf/vczjk/l94;->_parserFeatures:I

    iget p2, p1, Llyiahf/vczjk/l94;->_generatorFeatures:I

    iput p2, p0, Llyiahf/vczjk/l94;->_generatorFeatures:I

    iget-object p2, p1, Llyiahf/vczjk/l94;->_rootValueSeparator:Llyiahf/vczjk/fg8;

    iput-object p2, p0, Llyiahf/vczjk/l94;->_rootValueSeparator:Llyiahf/vczjk/fg8;

    iget p2, p1, Llyiahf/vczjk/l94;->_maximumNonEscapedChar:I

    iput p2, p0, Llyiahf/vczjk/l94;->_maximumNonEscapedChar:I

    iget-char p1, p1, Llyiahf/vczjk/l94;->_quoteChar:C

    iput-char p1, p0, Llyiahf/vczjk/l94;->_quoteChar:C

    return-void
.end method


# virtual methods
.method public final OooO00o(Ljava/lang/Object;Z)Llyiahf/vczjk/t01;
    .locals 2

    new-instance v0, Llyiahf/vczjk/t01;

    invoke-virtual {p0}, Llyiahf/vczjk/l94;->OooO0O0()Llyiahf/vczjk/bj0;

    move-result-object v1

    invoke-direct {v0, v1, p1, p2}, Llyiahf/vczjk/t01;-><init>(Llyiahf/vczjk/bj0;Ljava/lang/Object;Z)V

    return-object v0
.end method

.method public final OooO0O0()Llyiahf/vczjk/bj0;
    .locals 6

    sget-object v0, Llyiahf/vczjk/k94;->OooOOOo:Llyiahf/vczjk/k94;

    iget v1, p0, Llyiahf/vczjk/l94;->_factoryFeatures:I

    invoke-virtual {v0, v1}, Llyiahf/vczjk/k94;->OooO0O0(I)Z

    move-result v0

    if-eqz v0, :cond_4

    sget-object v0, Llyiahf/vczjk/cj0;->OooO0O0:Ljava/lang/ThreadLocal;

    invoke-virtual {v0}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/ref/SoftReference;

    if-nez v1, :cond_0

    const/4 v1, 0x0

    goto :goto_0

    :cond_0
    invoke-virtual {v1}, Ljava/lang/ref/SoftReference;->get()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/bj0;

    :goto_0
    if-nez v1, :cond_3

    new-instance v1, Llyiahf/vczjk/bj0;

    invoke-direct {v1}, Llyiahf/vczjk/bj0;-><init>()V

    sget-object v2, Llyiahf/vczjk/cj0;->OooO00o:Llyiahf/vczjk/qx7;

    if-eqz v2, :cond_1

    new-instance v3, Ljava/lang/ref/SoftReference;

    iget-object v4, v2, Llyiahf/vczjk/qx7;->OooOOO:Ljava/lang/Object;

    check-cast v4, Ljava/lang/ref/ReferenceQueue;

    invoke-direct {v3, v1, v4}, Ljava/lang/ref/SoftReference;-><init>(Ljava/lang/Object;Ljava/lang/ref/ReferenceQueue;)V

    iget-object v2, v2, Llyiahf/vczjk/qx7;->OooOOO0:Ljava/lang/Object;

    check-cast v2, Ljava/util/concurrent/ConcurrentHashMap;

    sget-object v5, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    invoke-virtual {v2, v3, v5}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :goto_1
    invoke-virtual {v4}, Ljava/lang/ref/ReferenceQueue;->poll()Ljava/lang/ref/Reference;

    move-result-object v5

    check-cast v5, Ljava/lang/ref/SoftReference;

    if-eqz v5, :cond_2

    invoke-virtual {v2, v5}, Ljava/util/concurrent/ConcurrentHashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_1

    :cond_1
    new-instance v3, Ljava/lang/ref/SoftReference;

    invoke-direct {v3, v1}, Ljava/lang/ref/SoftReference;-><init>(Ljava/lang/Object;)V

    :cond_2
    invoke-virtual {v0, v3}, Ljava/lang/ThreadLocal;->set(Ljava/lang/Object;)V

    :cond_3
    return-object v1

    :cond_4
    new-instance v0, Llyiahf/vczjk/bj0;

    invoke-direct {v0}, Llyiahf/vczjk/bj0;-><init>()V

    return-object v0
.end method

.method public OooO0OO(Llyiahf/vczjk/pl0;)Llyiahf/vczjk/u94;
    .locals 4

    sget-object v0, Llyiahf/vczjk/i94;->OooOOO0:Llyiahf/vczjk/i94;

    const/4 v1, 0x0

    invoke-virtual {p0, p1, v1}, Llyiahf/vczjk/l94;->OooO00o(Ljava/lang/Object;Z)Llyiahf/vczjk/t01;

    move-result-object v1

    iput-object v0, v1, Llyiahf/vczjk/t01;->OooO0OO:Ljava/io/Serializable;

    new-instance v0, Llyiahf/vczjk/c7a;

    iget v2, p0, Llyiahf/vczjk/l94;->_generatorFeatures:I

    iget-char v3, p0, Llyiahf/vczjk/l94;->_quoteChar:C

    invoke-direct {v0, v1, v2, p1, v3}, Llyiahf/vczjk/c7a;-><init>(Llyiahf/vczjk/t01;ILlyiahf/vczjk/pl0;C)V

    iget p1, p0, Llyiahf/vczjk/l94;->_maximumNonEscapedChar:I

    if-lez p1, :cond_0

    invoke-virtual {v0, p1}, Llyiahf/vczjk/v94;->OoooOoo(I)V

    :cond_0
    iget-object p1, p0, Llyiahf/vczjk/l94;->_rootValueSeparator:Llyiahf/vczjk/fg8;

    sget-object v1, Llyiahf/vczjk/l94;->OooOOo:Llyiahf/vczjk/ng8;

    if-eq p1, v1, :cond_1

    iput-object p1, v0, Llyiahf/vczjk/v94;->OooOo0:Llyiahf/vczjk/fg8;

    :cond_1
    return-object v0
.end method

.method public OooO0Oo()Llyiahf/vczjk/l66;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/l94;->_objectCodec:Llyiahf/vczjk/l66;

    return-object v0
.end method

.method public readResolve()Ljava/lang/Object;
    .locals 2

    new-instance v0, Llyiahf/vczjk/l94;

    iget-object v1, p0, Llyiahf/vczjk/l94;->_objectCodec:Llyiahf/vczjk/l66;

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/l94;-><init>(Llyiahf/vczjk/l94;Llyiahf/vczjk/l66;)V

    return-object v0
.end method
