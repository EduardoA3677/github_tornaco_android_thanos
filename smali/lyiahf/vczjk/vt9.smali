.class public final Llyiahf/vczjk/vt9;
.super Llyiahf/vczjk/b23;
.source "SourceFile"


# instance fields
.field public final OooO0Oo:Llyiahf/vczjk/b23;

.field public OooO0o:Ljava/lang/String;

.field public final OooO0o0:Llyiahf/vczjk/ia4;

.field public OooO0oO:Ljava/lang/Object;


# direct methods
.method public constructor <init>()V
    .locals 1

    const/4 v0, 0x0

    invoke-direct {p0, v0}, Llyiahf/vczjk/b23;-><init>(I)V

    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/vt9;->OooO0Oo:Llyiahf/vczjk/b23;

    sget-object v0, Llyiahf/vczjk/ia4;->OooOOO:Llyiahf/vczjk/ia4;

    iput-object v0, p0, Llyiahf/vczjk/vt9;->OooO0o0:Llyiahf/vczjk/ia4;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/b23;Llyiahf/vczjk/ia4;)V
    .locals 1

    invoke-direct {p0}, Llyiahf/vczjk/b23;-><init>()V

    iget v0, p1, Llyiahf/vczjk/b23;->OooO0O0:I

    iput v0, p0, Llyiahf/vczjk/b23;->OooO0O0:I

    iget v0, p1, Llyiahf/vczjk/b23;->OooO0OO:I

    iput v0, p0, Llyiahf/vczjk/b23;->OooO0OO:I

    invoke-virtual {p1}, Llyiahf/vczjk/b23;->OooO0o()Llyiahf/vczjk/b23;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/vt9;->OooO0Oo:Llyiahf/vczjk/b23;

    invoke-virtual {p1}, Llyiahf/vczjk/b23;->OooO0Oo()Ljava/lang/String;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/vt9;->OooO0o:Ljava/lang/String;

    invoke-virtual {p1}, Llyiahf/vczjk/b23;->OooO0o0()Ljava/lang/Object;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/vt9;->OooO0oO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/vt9;->OooO0o0:Llyiahf/vczjk/ia4;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/vt9;I)V
    .locals 0

    invoke-direct {p0, p2}, Llyiahf/vczjk/b23;-><init>(I)V

    iput-object p1, p0, Llyiahf/vczjk/vt9;->OooO0Oo:Llyiahf/vczjk/b23;

    iget-object p1, p1, Llyiahf/vczjk/vt9;->OooO0o0:Llyiahf/vczjk/ia4;

    iput-object p1, p0, Llyiahf/vczjk/vt9;->OooO0o0:Llyiahf/vczjk/ia4;

    return-void
.end method


# virtual methods
.method public final OooO0Oo()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vt9;->OooO0o:Ljava/lang/String;

    return-object v0
.end method

.method public final OooO0o()Llyiahf/vczjk/b23;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vt9;->OooO0Oo:Llyiahf/vczjk/b23;

    return-object v0
.end method

.method public final OooO0o0()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vt9;->OooO0oO:Ljava/lang/Object;

    return-object v0
.end method

.method public final OooOO0(Ljava/lang/Object;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/vt9;->OooO0oO:Ljava/lang/Object;

    return-void
.end method
