.class public final Llyiahf/vczjk/w29;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Z

.field public final OooO0O0:Llyiahf/vczjk/le3;

.field public final OooO0OO:Llyiahf/vczjk/gi;

.field public final OooO0Oo:Ljava/util/ArrayList;

.field public OooO0o0:Llyiahf/vczjk/j24;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/le3;Z)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p2, p0, Llyiahf/vczjk/w29;->OooO00o:Z

    iput-object p1, p0, Llyiahf/vczjk/w29;->OooO0O0:Llyiahf/vczjk/le3;

    const/4 p1, 0x0

    invoke-static {p1}, Llyiahf/vczjk/mc4;->OooO0O0(F)Llyiahf/vczjk/gi;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/w29;->OooO0OO:Llyiahf/vczjk/gi;

    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/w29;->OooO0Oo:Ljava/util/ArrayList;

    return-void
.end method
