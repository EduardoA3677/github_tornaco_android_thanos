.class public abstract Llyiahf/vczjk/ct4;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/wz8;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    const/4 v0, 0x1

    int-to-long v1, v0

    const/16 v3, 0x20

    shl-long v3, v1, v3

    const-wide v5, 0xffffffffL

    and-long/2addr v1, v5

    or-long/2addr v1, v3

    new-instance v3, Llyiahf/vczjk/u14;

    invoke-direct {v3, v1, v2}, Llyiahf/vczjk/u14;-><init>(J)V

    const/4 v1, 0x0

    const/high16 v2, 0x43c80000    # 400.0f

    invoke-static {v1, v2, v3, v0}, Llyiahf/vczjk/ng0;->OoooOoo(FFLjava/lang/Object;I)Llyiahf/vczjk/wz8;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/ct4;->OooO00o:Llyiahf/vczjk/wz8;

    return-void
.end method
