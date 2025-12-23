.class public final Llyiahf/vczjk/sg8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/io/Serializable;


# static fields
.field public static final OooOOO:[Llyiahf/vczjk/lb0;

.field public static final OooOOO0:[Llyiahf/vczjk/ug8;

.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected final _additionalKeySerializers:[Llyiahf/vczjk/ug8;

.field protected final _additionalSerializers:[Llyiahf/vczjk/ug8;

.field protected final _modifiers:[Llyiahf/vczjk/lb0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    const/4 v0, 0x0

    new-array v1, v0, [Llyiahf/vczjk/ug8;

    sput-object v1, Llyiahf/vczjk/sg8;->OooOOO0:[Llyiahf/vczjk/ug8;

    new-array v0, v0, [Llyiahf/vczjk/lb0;

    sput-object v0, Llyiahf/vczjk/sg8;->OooOOO:[Llyiahf/vczjk/lb0;

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    sget-object v0, Llyiahf/vczjk/sg8;->OooOOO0:[Llyiahf/vczjk/ug8;

    iput-object v0, p0, Llyiahf/vczjk/sg8;->_additionalSerializers:[Llyiahf/vczjk/ug8;

    iput-object v0, p0, Llyiahf/vczjk/sg8;->_additionalKeySerializers:[Llyiahf/vczjk/ug8;

    sget-object v0, Llyiahf/vczjk/sg8;->OooOOO:[Llyiahf/vczjk/lb0;

    iput-object v0, p0, Llyiahf/vczjk/sg8;->_modifiers:[Llyiahf/vczjk/lb0;

    return-void
.end method


# virtual methods
.method public final OooO00o()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/sg8;->_modifiers:[Llyiahf/vczjk/lb0;

    array-length v0, v0

    if-lez v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooO0O0()Llyiahf/vczjk/yx;
    .locals 2

    new-instance v0, Llyiahf/vczjk/yx;

    iget-object v1, p0, Llyiahf/vczjk/sg8;->_modifiers:[Llyiahf/vczjk/lb0;

    invoke-direct {v0, v1}, Llyiahf/vczjk/yx;-><init>([Ljava/lang/Object;)V

    return-object v0
.end method

.method public final OooO0OO()Llyiahf/vczjk/yx;
    .locals 2

    new-instance v0, Llyiahf/vczjk/yx;

    iget-object v1, p0, Llyiahf/vczjk/sg8;->_additionalSerializers:[Llyiahf/vczjk/ug8;

    invoke-direct {v0, v1}, Llyiahf/vczjk/yx;-><init>([Ljava/lang/Object;)V

    return-object v0
.end method
