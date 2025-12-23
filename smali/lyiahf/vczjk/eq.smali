.class public final Llyiahf/vczjk/eq;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO0OO:Llyiahf/vczjk/era;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/qr5;

.field public final OooO0O0:Llyiahf/vczjk/qr5;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    new-instance v0, Llyiahf/vczjk/v1;

    const/16 v1, 0xb

    invoke-direct {v0, v1}, Llyiahf/vczjk/v1;-><init>(I)V

    new-instance v1, Llyiahf/vczjk/b2;

    const/16 v2, 0x19

    invoke-direct {v1, v2}, Llyiahf/vczjk/b2;-><init>(I)V

    sget-object v2, Llyiahf/vczjk/l68;->OooO00o:Llyiahf/vczjk/era;

    new-instance v2, Llyiahf/vczjk/era;

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/era;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    sput-object v2, Llyiahf/vczjk/eq;->OooO0OO:Llyiahf/vczjk/era;

    return-void
.end method

.method public constructor <init>()V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    invoke-static {v0}, Landroidx/compose/runtime/OooO0o;->OooO0oO(I)Llyiahf/vczjk/qr5;

    move-result-object v1

    iput-object v1, p0, Llyiahf/vczjk/eq;->OooO00o:Llyiahf/vczjk/qr5;

    invoke-static {v0}, Landroidx/compose/runtime/OooO0o;->OooO0oO(I)Llyiahf/vczjk/qr5;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/eq;->OooO0O0:Llyiahf/vczjk/qr5;

    return-void
.end method
