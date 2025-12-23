.class public final Llyiahf/vczjk/yc0;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/zs2;

.field public final OooO0O0:Llyiahf/vczjk/ff8;


# direct methods
.method public constructor <init>(ILlyiahf/vczjk/zs2;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/yc0;->OooO00o:Llyiahf/vczjk/zs2;

    sget p2, Llyiahf/vczjk/gf8;->OooO00o:I

    new-instance p2, Llyiahf/vczjk/ff8;

    invoke-direct {p2, p1}, Llyiahf/vczjk/ef8;-><init>(I)V

    iput-object p2, p0, Llyiahf/vczjk/yc0;->OooO0O0:Llyiahf/vczjk/ff8;

    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 0

    instance-of p1, p1, Llyiahf/vczjk/yc0;

    return p1
.end method

.method public final hashCode()I
    .locals 1

    const-class v0, Llyiahf/vczjk/yc0;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    return v0
.end method
