.class public final Llyiahf/vczjk/iqa;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/rb3;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/rqa;

.field public final OooO0O0:Llyiahf/vczjk/n77;

.field public final OooO0OO:Llyiahf/vczjk/bra;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    const-string v0, "WMFgUpdater"

    invoke-static {v0}, Llyiahf/vczjk/o55;->OooOOOO(Ljava/lang/String;)Ljava/lang/String;

    return-void
.end method

.method public constructor <init>(Landroidx/work/impl/WorkDatabase;Llyiahf/vczjk/n77;Llyiahf/vczjk/rqa;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/iqa;->OooO0O0:Llyiahf/vczjk/n77;

    iput-object p3, p0, Llyiahf/vczjk/iqa;->OooO00o:Llyiahf/vczjk/rqa;

    invoke-virtual {p1}, Landroidx/work/impl/WorkDatabase;->OooO0oo()Llyiahf/vczjk/bra;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/iqa;->OooO0OO:Llyiahf/vczjk/bra;

    return-void
.end method
