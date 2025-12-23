.class public final Llyiahf/vczjk/y90;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $displayedText$delegate:Llyiahf/vczjk/qs5;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/qs5;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/qs5;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/y90;->$displayedText$delegate:Llyiahf/vczjk/qs5;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/fh9;

    iget-object v0, p0, Llyiahf/vczjk/y90;->$displayedText$delegate:Llyiahf/vczjk/qs5;

    iget-boolean v1, p1, Llyiahf/vczjk/fh9;->OooO0OO:Z

    if-eqz v1, :cond_0

    iget-object p1, p1, Llyiahf/vczjk/fh9;->OooO0O0:Llyiahf/vczjk/an;

    goto :goto_0

    :cond_0
    iget-object p1, p1, Llyiahf/vczjk/fh9;->OooO00o:Llyiahf/vczjk/an;

    :goto_0
    invoke-interface {v0, p1}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
