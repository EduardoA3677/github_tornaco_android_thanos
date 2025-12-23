.class public abstract Llyiahf/vczjk/jk2;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/cu1;

.field public static final OooO0O0:Llyiahf/vczjk/cu1;

.field public static final OooO0OO:Llyiahf/vczjk/cu1;

.field public static final OooO0Oo:Llyiahf/vczjk/oOO0O00O;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    new-instance v0, Llyiahf/vczjk/cu1;

    const v1, 0x3ecccccd    # 0.4f

    const/4 v2, 0x0

    const v3, 0x3e4ccccd    # 0.2f

    const/high16 v4, 0x3f800000    # 1.0f

    invoke-direct {v0, v1, v2, v3, v4}, Llyiahf/vczjk/cu1;-><init>(FFFF)V

    sput-object v0, Llyiahf/vczjk/jk2;->OooO00o:Llyiahf/vczjk/cu1;

    new-instance v0, Llyiahf/vczjk/cu1;

    invoke-direct {v0, v2, v2, v3, v4}, Llyiahf/vczjk/cu1;-><init>(FFFF)V

    sput-object v0, Llyiahf/vczjk/jk2;->OooO0O0:Llyiahf/vczjk/cu1;

    new-instance v0, Llyiahf/vczjk/cu1;

    invoke-direct {v0, v1, v2, v4, v4}, Llyiahf/vczjk/cu1;-><init>(FFFF)V

    sput-object v0, Llyiahf/vczjk/jk2;->OooO0OO:Llyiahf/vczjk/cu1;

    new-instance v0, Llyiahf/vczjk/oOO0O00O;

    const/16 v1, 0x1d

    invoke-direct {v0, v1}, Llyiahf/vczjk/oOO0O00O;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/jk2;->OooO0Oo:Llyiahf/vczjk/oOO0O00O;

    return-void
.end method
