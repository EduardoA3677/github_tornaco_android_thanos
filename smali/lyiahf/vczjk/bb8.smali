.class public final Llyiahf/vczjk/bb8;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/db8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/db8;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/bb8;->this$0:Llyiahf/vczjk/db8;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Llyiahf/vczjk/p86;

    iget-wide v0, p1, Llyiahf/vczjk/p86;->OooO00o:J

    iget-object p1, p0, Llyiahf/vczjk/bb8;->this$0:Llyiahf/vczjk/db8;

    iget-object v2, p1, Llyiahf/vczjk/db8;->OooOO0:Llyiahf/vczjk/v98;

    iget v3, p1, Llyiahf/vczjk/db8;->OooO:I

    invoke-static {p1, v2, v0, v1, v3}, Llyiahf/vczjk/db8;->OooO00o(Llyiahf/vczjk/db8;Llyiahf/vczjk/v98;JI)J

    move-result-wide v0

    new-instance p1, Llyiahf/vczjk/p86;

    invoke-direct {p1, v0, v1}, Llyiahf/vczjk/p86;-><init>(J)V

    return-object p1
.end method
