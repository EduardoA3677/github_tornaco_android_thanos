.class public abstract Llyiahf/vczjk/r6a;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/n6a;


# direct methods
.method static constructor <clinit>()V
    .locals 14

    new-instance v0, Llyiahf/vczjk/n6a;

    sget-object v7, Llyiahf/vczjk/ba3;->OooOOO0:Llyiahf/vczjk/g22;

    sget-object v6, Llyiahf/vczjk/ib3;->OooOOoo:Llyiahf/vczjk/ib3;

    const/16 v1, 0x10

    invoke-static {v1}, Llyiahf/vczjk/eo6;->OooOO0o(I)J

    move-result-wide v4

    const/16 v1, 0x18

    invoke-static {v1}, Llyiahf/vczjk/eo6;->OooOO0o(I)J

    move-result-wide v11

    const-wide/high16 v1, 0x3fe0000000000000L    # 0.5

    invoke-static {v1, v2}, Llyiahf/vczjk/eo6;->OooOO0O(D)J

    move-result-wide v8

    new-instance v1, Llyiahf/vczjk/rn9;

    const-wide/16 v2, 0x0

    const/4 v10, 0x0

    const v13, 0xfdff59

    invoke-direct/range {v1 .. v13}, Llyiahf/vczjk/rn9;-><init>(JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ba3;JIJI)V

    const/16 v2, 0x7dff

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/n6a;-><init>(Llyiahf/vczjk/rn9;I)V

    sput-object v0, Llyiahf/vczjk/r6a;->OooO00o:Llyiahf/vczjk/n6a;

    return-void
.end method
