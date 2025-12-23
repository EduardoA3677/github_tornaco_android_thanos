.class public final Llyiahf/vczjk/be0;
.super Llyiahf/vczjk/pca;
.source "SourceFile"


# static fields
.field public static final OooOOO:Llyiahf/vczjk/be0;

.field public static final OooOOO0:Llyiahf/vczjk/be0;

.field private static final serialVersionUID:J = 0x2L


# instance fields
.field private final _value:Z


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/be0;

    const/4 v1, 0x1

    invoke-direct {v0, v1}, Llyiahf/vczjk/be0;-><init>(Z)V

    sput-object v0, Llyiahf/vczjk/be0;->OooOOO0:Llyiahf/vczjk/be0;

    new-instance v0, Llyiahf/vczjk/be0;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/be0;-><init>(Z)V

    sput-object v0, Llyiahf/vczjk/be0;->OooOOO:Llyiahf/vczjk/be0;

    return-void
.end method

.method public constructor <init>(Z)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Llyiahf/vczjk/be0;->_value:Z

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 0

    iget-boolean p2, p0, Llyiahf/vczjk/be0;->_value:Z

    invoke-virtual {p1, p2}, Llyiahf/vczjk/u94;->o000OOo(Z)V

    return-void
.end method

.method public final OooO0o()Llyiahf/vczjk/gc4;
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/be0;->_value:Z

    if-eqz v0, :cond_0

    sget-object v0, Llyiahf/vczjk/gc4;->OooOo0o:Llyiahf/vczjk/gc4;

    return-object v0

    :cond_0
    sget-object v0, Llyiahf/vczjk/gc4;->OooOo:Llyiahf/vczjk/gc4;

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
    instance-of v2, p1, Llyiahf/vczjk/be0;

    if-nez v2, :cond_2

    return v1

    :cond_2
    iget-boolean v2, p0, Llyiahf/vczjk/be0;->_value:Z

    check-cast p1, Llyiahf/vczjk/be0;

    iget-boolean p1, p1, Llyiahf/vczjk/be0;->_value:Z

    if-ne v2, p1, :cond_3

    return v0

    :cond_3
    return v1
.end method

.method public final hashCode()I
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/be0;->_value:Z

    if-eqz v0, :cond_0

    const/4 v0, 0x3

    return v0

    :cond_0
    const/4 v0, 0x1

    return v0
.end method

.method public readResolve()Ljava/lang/Object;
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/be0;->_value:Z

    if-eqz v0, :cond_0

    sget-object v0, Llyiahf/vczjk/be0;->OooOOO0:Llyiahf/vczjk/be0;

    return-object v0

    :cond_0
    sget-object v0, Llyiahf/vczjk/be0;->OooOOO:Llyiahf/vczjk/be0;

    return-object v0
.end method
