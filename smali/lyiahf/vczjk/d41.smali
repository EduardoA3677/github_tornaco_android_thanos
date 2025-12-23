.class public final Llyiahf/vczjk/d41;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/g41;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/g41;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/d41;->this$0:Llyiahf/vczjk/g41;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/p86;

    iget-wide v0, p1, Llyiahf/vczjk/p86;->OooO00o:J

    iget-object p1, p0, Llyiahf/vczjk/d41;->this$0:Llyiahf/vczjk/g41;

    iget-boolean v0, p1, Llyiahf/vczjk/o0000O0O;->Oooo00O:Z

    if-eqz v0, :cond_0

    iget-object p1, p1, Llyiahf/vczjk/o0000O0O;->Oooo00o:Llyiahf/vczjk/le3;

    invoke-interface {p1}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
