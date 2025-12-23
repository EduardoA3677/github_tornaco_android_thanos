.class public final Llyiahf/vczjk/dda;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/fda;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/fda;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/dda;->this$0:Llyiahf/vczjk/fda;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/yba;

    iget-object p1, p0, Llyiahf/vczjk/dda;->this$0:Llyiahf/vczjk/fda;

    const/4 v0, 0x1

    iput-boolean v0, p1, Llyiahf/vczjk/fda;->OooO0Oo:Z

    iget-object p1, p1, Llyiahf/vczjk/fda;->OooO0o:Llyiahf/vczjk/rm4;

    invoke-interface {p1}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
