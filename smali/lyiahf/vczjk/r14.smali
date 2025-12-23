.class public final Llyiahf/vczjk/r14;
.super Llyiahf/vczjk/g66;
.source "SourceFile"


# static fields
.field public static final OooOOO0:[Llyiahf/vczjk/r14;


# instance fields
.field protected final _value:I


# direct methods
.method static constructor <clinit>()V
    .locals 5

    const/16 v0, 0xc

    new-array v1, v0, [Llyiahf/vczjk/r14;

    sput-object v1, Llyiahf/vczjk/r14;->OooOOO0:[Llyiahf/vczjk/r14;

    const/4 v1, 0x0

    :goto_0
    if-ge v1, v0, :cond_0

    sget-object v2, Llyiahf/vczjk/r14;->OooOOO0:[Llyiahf/vczjk/r14;

    new-instance v3, Llyiahf/vczjk/r14;

    add-int/lit8 v4, v1, -0x1

    invoke-direct {v3, v4}, Llyiahf/vczjk/r14;-><init>(I)V

    aput-object v3, v2, v1

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_0
    return-void
.end method

.method public constructor <init>(I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Llyiahf/vczjk/r14;->_value:I

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 0

    iget p2, p0, Llyiahf/vczjk/r14;->_value:I

    invoke-virtual {p1, p2}, Llyiahf/vczjk/u94;->o0000oo(I)V

    return-void
.end method

.method public final OooO0o()Llyiahf/vczjk/gc4;
    .locals 1

    sget-object v0, Llyiahf/vczjk/gc4;->OooOo0:Llyiahf/vczjk/gc4;

    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 3

    const/4 v0, 0x1

    if-ne p1, p0, :cond_0

    return v0

    :cond_0
    const/4 v1, 0x0

    if-nez p1, :cond_1

    return v1

    :cond_1
    instance-of v2, p1, Llyiahf/vczjk/r14;

    if-eqz v2, :cond_2

    check-cast p1, Llyiahf/vczjk/r14;

    iget p1, p1, Llyiahf/vczjk/r14;->_value:I

    iget v2, p0, Llyiahf/vczjk/r14;->_value:I

    if-ne p1, v2, :cond_2

    return v0

    :cond_2
    return v1
.end method

.method public final hashCode()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/r14;->_value:I

    return v0
.end method
