.class public final Llyiahf/vczjk/c1a;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/fm1;
.implements Llyiahf/vczjk/z70;


# instance fields
.field public final OooO00o:Z

.field public final OooO0O0:Ljava/util/ArrayList;

.field public final OooO0OO:I

.field public final OooO0Oo:Llyiahf/vczjk/w23;

.field public final OooO0o:Llyiahf/vczjk/w23;

.field public final OooO0o0:Llyiahf/vczjk/w23;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/f80;Llyiahf/vczjk/tk8;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/c1a;->OooO0O0:Ljava/util/ArrayList;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-boolean v0, p2, Llyiahf/vczjk/tk8;->OooO0o0:Z

    iput-boolean v0, p0, Llyiahf/vczjk/c1a;->OooO00o:Z

    iget v0, p2, Llyiahf/vczjk/tk8;->OooO00o:I

    iput v0, p0, Llyiahf/vczjk/c1a;->OooO0OO:I

    iget-object v0, p2, Llyiahf/vczjk/tk8;->OooO0O0:Llyiahf/vczjk/ii;

    invoke-virtual {v0}, Llyiahf/vczjk/ii;->o0000oo()Llyiahf/vczjk/w23;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/c1a;->OooO0Oo:Llyiahf/vczjk/w23;

    iget-object v1, p2, Llyiahf/vczjk/tk8;->OooO0OO:Llyiahf/vczjk/ii;

    invoke-virtual {v1}, Llyiahf/vczjk/ii;->o0000oo()Llyiahf/vczjk/w23;

    move-result-object v1

    iput-object v1, p0, Llyiahf/vczjk/c1a;->OooO0o0:Llyiahf/vczjk/w23;

    iget-object p2, p2, Llyiahf/vczjk/tk8;->OooO0Oo:Llyiahf/vczjk/ii;

    invoke-virtual {p2}, Llyiahf/vczjk/ii;->o0000oo()Llyiahf/vczjk/w23;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/c1a;->OooO0o:Llyiahf/vczjk/w23;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/f80;->OooO0o0(Llyiahf/vczjk/d80;)V

    invoke-virtual {p1, v1}, Llyiahf/vczjk/f80;->OooO0o0(Llyiahf/vczjk/d80;)V

    invoke-virtual {p1, p2}, Llyiahf/vczjk/f80;->OooO0o0(Llyiahf/vczjk/d80;)V

    invoke-virtual {v0, p0}, Llyiahf/vczjk/d80;->OooO00o(Llyiahf/vczjk/z70;)V

    invoke-virtual {v1, p0}, Llyiahf/vczjk/d80;->OooO00o(Llyiahf/vczjk/z70;)V

    invoke-virtual {p2, p0}, Llyiahf/vczjk/d80;->OooO00o(Llyiahf/vczjk/z70;)V

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 3

    const/4 v0, 0x0

    :goto_0
    iget-object v1, p0, Llyiahf/vczjk/c1a;->OooO0O0:Ljava/util/ArrayList;

    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    move-result v2

    if-ge v0, v2, :cond_0

    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/z70;

    invoke-interface {v1}, Llyiahf/vczjk/z70;->OooO00o()V

    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_0
    return-void
.end method

.method public final OooO0O0(Ljava/util/List;Ljava/util/List;)V
    .locals 0

    return-void
.end method

.method public final OooO0OO(Llyiahf/vczjk/z70;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/c1a;->OooO0O0:Ljava/util/ArrayList;

    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-void
.end method
