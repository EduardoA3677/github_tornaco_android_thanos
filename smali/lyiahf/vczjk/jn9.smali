.class public abstract Llyiahf/vczjk/jn9;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/jh1;

.field public static final OooO0O0:Llyiahf/vczjk/in9;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    sget-object v0, Llyiahf/vczjk/o24;->Oooo000:Llyiahf/vczjk/o24;

    new-instance v1, Llyiahf/vczjk/jh1;

    invoke-direct {v1, v0}, Llyiahf/vczjk/jh1;-><init>(Llyiahf/vczjk/le3;)V

    sput-object v1, Llyiahf/vczjk/jn9;->OooO00o:Llyiahf/vczjk/jh1;

    const-wide v0, 0xff4286f4L

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooO0o0(J)J

    move-result-wide v0

    new-instance v2, Llyiahf/vczjk/in9;

    const v3, 0x3ecccccd    # 0.4f

    invoke-static {v3, v0, v1}, Llyiahf/vczjk/n21;->OooO0O0(FJ)J

    move-result-wide v3

    invoke-direct {v2, v0, v1, v3, v4}, Llyiahf/vczjk/in9;-><init>(JJ)V

    sput-object v2, Llyiahf/vczjk/jn9;->OooO0O0:Llyiahf/vczjk/in9;

    return-void
.end method
