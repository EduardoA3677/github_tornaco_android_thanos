.class public final Llyiahf/vczjk/ge2;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $event:Llyiahf/vczjk/de2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/de2;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ge2;->$event:Llyiahf/vczjk/de2;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Llyiahf/vczjk/ie2;

    iget-object v0, p1, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget-boolean v0, v0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-nez v0, :cond_0

    sget-object p1, Llyiahf/vczjk/b0a;->OooOOO:Llyiahf/vczjk/b0a;

    return-object p1

    :cond_0
    iget-object v0, p1, Llyiahf/vczjk/ie2;->OooOoo0:Llyiahf/vczjk/ie2;

    if-eqz v0, :cond_2

    iget-object v1, p0, Llyiahf/vczjk/ge2;->$event:Llyiahf/vczjk/de2;

    new-instance v2, Llyiahf/vczjk/ge2;

    invoke-direct {v2, v1}, Llyiahf/vczjk/ge2;-><init>(Llyiahf/vczjk/de2;)V

    invoke-virtual {v2, v0}, Llyiahf/vczjk/ge2;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    sget-object v3, Llyiahf/vczjk/b0a;->OooOOO0:Llyiahf/vczjk/b0a;

    if-eq v1, v3, :cond_1

    goto :goto_0

    :cond_1
    invoke-static {v0, v2}, Llyiahf/vczjk/er8;->OooOo(Llyiahf/vczjk/c0a;Llyiahf/vczjk/oe3;)V

    :cond_2
    :goto_0
    const/4 v0, 0x0

    iput-object v0, p1, Llyiahf/vczjk/ie2;->OooOoo0:Llyiahf/vczjk/ie2;

    iput-object v0, p1, Llyiahf/vczjk/ie2;->OooOoOO:Llyiahf/vczjk/ie2;

    sget-object p1, Llyiahf/vczjk/b0a;->OooOOO0:Llyiahf/vczjk/b0a;

    return-object p1
.end method
