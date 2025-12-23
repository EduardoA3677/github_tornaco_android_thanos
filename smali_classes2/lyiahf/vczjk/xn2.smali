.class public final Llyiahf/vczjk/xn2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/un;


# static fields
.field public static final OooO00o:Llyiahf/vczjk/xn2;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/xn2;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/xn2;->OooO00o:Llyiahf/vczjk/xn2;

    return-void
.end method


# virtual methods
.method public final OooO()Ljava/util/Map;
    .locals 2

    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "No methods should be called on this descriptor. Only its presence matters"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public final OooO0oO()Llyiahf/vczjk/sx8;
    .locals 2

    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "No methods should be called on this descriptor. Only its presence matters"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public final OooO0oo()Llyiahf/vczjk/hc3;
    .locals 3

    invoke-static {p0}, Llyiahf/vczjk/p72;->OooO0Oo(Llyiahf/vczjk/un;)Llyiahf/vczjk/by0;

    move-result-object v0

    const/4 v1, 0x0

    if-eqz v0, :cond_1

    invoke-static {v0}, Llyiahf/vczjk/uq2;->OooO0o(Llyiahf/vczjk/v02;)Z

    move-result v2

    if-nez v2, :cond_0

    goto :goto_0

    :cond_0
    move-object v0, v1

    :goto_0
    if-eqz v0, :cond_1

    invoke-static {v0}, Llyiahf/vczjk/p72;->OooO0OO(Llyiahf/vczjk/x02;)Llyiahf/vczjk/hc3;

    move-result-object v0

    return-object v0

    :cond_1
    return-object v1
.end method

.method public final getType()Llyiahf/vczjk/uk4;
    .locals 2

    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "No methods should be called on this descriptor. Only its presence matters"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    const-string v0, "[EnhancedType]"

    return-object v0
.end method
