.class public final Llyiahf/vczjk/zs6;
.super Llyiahf/vczjk/o00OOOO0;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/at6;


# static fields
.field public static final OooOOOo:Llyiahf/vczjk/zs6;


# instance fields
.field public final OooOOO:Ljava/lang/Object;

.field public final OooOOO0:Ljava/lang/Object;

.field public final OooOOOO:Llyiahf/vczjk/qs6;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    new-instance v0, Llyiahf/vczjk/zs6;

    sget-object v1, Llyiahf/vczjk/vp3;->OooOOOo:Llyiahf/vczjk/vp3;

    sget-object v2, Llyiahf/vczjk/qs6;->OooOOOO:Llyiahf/vczjk/qs6;

    invoke-direct {v0, v1, v1, v2}, Llyiahf/vczjk/zs6;-><init>(Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/qs6;)V

    sput-object v0, Llyiahf/vczjk/zs6;->OooOOOo:Llyiahf/vczjk/zs6;

    return-void
.end method

.method public constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/qs6;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/zs6;->OooOOO0:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/zs6;->OooOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/zs6;->OooOOOO:Llyiahf/vczjk/qs6;

    return-void
.end method


# virtual methods
.method public final OooO00o()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zs6;->OooOOOO:Llyiahf/vczjk/qs6;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget v0, v0, Llyiahf/vczjk/qs6;->OooOOO:I

    return v0
.end method

.method public final contains(Ljava/lang/Object;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zs6;->OooOOOO:Llyiahf/vczjk/qs6;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/qs6;->containsKey(Ljava/lang/Object;)Z

    move-result p1

    return p1
.end method

.method public final iterator()Ljava/util/Iterator;
    .locals 3

    new-instance v0, Llyiahf/vczjk/zg3;

    iget-object v1, p0, Llyiahf/vczjk/zs6;->OooOOOO:Llyiahf/vczjk/qs6;

    iget-object v2, p0, Llyiahf/vczjk/zs6;->OooOOO0:Ljava/lang/Object;

    invoke-direct {v0, v2, v1}, Llyiahf/vczjk/zg3;-><init>(Ljava/lang/Object;Ljava/util/Map;)V

    return-object v0
.end method
