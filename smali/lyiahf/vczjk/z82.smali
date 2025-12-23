.class public final Llyiahf/vczjk/z82;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/io/Serializable;


# static fields
.field public static final OooOOO:[Llyiahf/vczjk/bb0;

.field public static final OooOOO0:[Llyiahf/vczjk/a92;

.field public static final OooOOOO:[Llyiahf/vczjk/o0O000Oo;

.field public static final OooOOOo:[Llyiahf/vczjk/oca;

.field public static final OooOOo0:[Llyiahf/vczjk/ui4;

.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected final _abstractTypeResolvers:[Llyiahf/vczjk/o0O000Oo;

.field protected final _additionalDeserializers:[Llyiahf/vczjk/a92;

.field protected final _additionalKeyDeserializers:[Llyiahf/vczjk/ui4;

.field protected final _modifiers:[Llyiahf/vczjk/bb0;

.field protected final _valueInstantiators:[Llyiahf/vczjk/oca;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    const/4 v0, 0x0

    new-array v1, v0, [Llyiahf/vczjk/a92;

    sput-object v1, Llyiahf/vczjk/z82;->OooOOO0:[Llyiahf/vczjk/a92;

    new-array v1, v0, [Llyiahf/vczjk/bb0;

    sput-object v1, Llyiahf/vczjk/z82;->OooOOO:[Llyiahf/vczjk/bb0;

    new-array v1, v0, [Llyiahf/vczjk/o0O000Oo;

    sput-object v1, Llyiahf/vczjk/z82;->OooOOOO:[Llyiahf/vczjk/o0O000Oo;

    new-array v1, v0, [Llyiahf/vczjk/oca;

    sput-object v1, Llyiahf/vczjk/z82;->OooOOOo:[Llyiahf/vczjk/oca;

    new-instance v1, Llyiahf/vczjk/w49;

    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    const/4 v2, 0x1

    new-array v2, v2, [Llyiahf/vczjk/ui4;

    aput-object v1, v2, v0

    sput-object v2, Llyiahf/vczjk/z82;->OooOOo0:[Llyiahf/vczjk/ui4;

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    sget-object v0, Llyiahf/vczjk/z82;->OooOOO0:[Llyiahf/vczjk/a92;

    iput-object v0, p0, Llyiahf/vczjk/z82;->_additionalDeserializers:[Llyiahf/vczjk/a92;

    sget-object v0, Llyiahf/vczjk/z82;->OooOOo0:[Llyiahf/vczjk/ui4;

    iput-object v0, p0, Llyiahf/vczjk/z82;->_additionalKeyDeserializers:[Llyiahf/vczjk/ui4;

    sget-object v0, Llyiahf/vczjk/z82;->OooOOO:[Llyiahf/vczjk/bb0;

    iput-object v0, p0, Llyiahf/vczjk/z82;->_modifiers:[Llyiahf/vczjk/bb0;

    sget-object v0, Llyiahf/vczjk/z82;->OooOOOO:[Llyiahf/vczjk/o0O000Oo;

    iput-object v0, p0, Llyiahf/vczjk/z82;->_abstractTypeResolvers:[Llyiahf/vczjk/o0O000Oo;

    sget-object v0, Llyiahf/vczjk/z82;->OooOOOo:[Llyiahf/vczjk/oca;

    iput-object v0, p0, Llyiahf/vczjk/z82;->_valueInstantiators:[Llyiahf/vczjk/oca;

    return-void
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/yx;
    .locals 2

    new-instance v0, Llyiahf/vczjk/yx;

    iget-object v1, p0, Llyiahf/vczjk/z82;->_abstractTypeResolvers:[Llyiahf/vczjk/o0O000Oo;

    invoke-direct {v0, v1}, Llyiahf/vczjk/yx;-><init>([Ljava/lang/Object;)V

    return-object v0
.end method

.method public final OooO0O0()Llyiahf/vczjk/yx;
    .locals 2

    new-instance v0, Llyiahf/vczjk/yx;

    iget-object v1, p0, Llyiahf/vczjk/z82;->_modifiers:[Llyiahf/vczjk/bb0;

    invoke-direct {v0, v1}, Llyiahf/vczjk/yx;-><init>([Ljava/lang/Object;)V

    return-object v0
.end method

.method public final OooO0OO()Llyiahf/vczjk/yx;
    .locals 2

    new-instance v0, Llyiahf/vczjk/yx;

    iget-object v1, p0, Llyiahf/vczjk/z82;->_additionalDeserializers:[Llyiahf/vczjk/a92;

    invoke-direct {v0, v1}, Llyiahf/vczjk/yx;-><init>([Ljava/lang/Object;)V

    return-object v0
.end method

.method public final OooO0Oo()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/z82;->_abstractTypeResolvers:[Llyiahf/vczjk/o0O000Oo;

    array-length v0, v0

    if-lez v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooO0o0()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/z82;->_modifiers:[Llyiahf/vczjk/bb0;

    array-length v0, v0

    if-lez v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method
