.class public final Llyiahf/vczjk/wm2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/or1;
.implements Ljava/io/Serializable;


# static fields
.field public static final OooOOO0:Llyiahf/vczjk/wm2;

.field private static final serialVersionUID:J


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/wm2;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/wm2;->OooOOO0:Llyiahf/vczjk/wm2;

    return-void
.end method

.method private final readResolve()Ljava/lang/Object;
    .locals 1

    sget-object v0, Llyiahf/vczjk/wm2;->OooOOO0:Llyiahf/vczjk/wm2;

    return-object v0
.end method


# virtual methods
.method public final OooOOOO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;
    .locals 1

    const-string v0, "context"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1
.end method

.method public final OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;
    .locals 1

    const-string v0, "key"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 p1, 0x0

    return-object p1
.end method

.method public final OooOoO(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/or1;
    .locals 1

    const-string v0, "key"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p0
.end method

.method public final hashCode()I
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final o000OOo(Ljava/lang/Object;Llyiahf/vczjk/ze3;)Ljava/lang/Object;
    .locals 0

    return-object p1
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    const-string v0, "EmptyCoroutineContext"

    return-object v0
.end method
