.class public final Llyiahf/vczjk/vs4;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $animationTarget:J

.field final synthetic this$0:Llyiahf/vczjk/bt4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bt4;J)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/vs4;->this$0:Llyiahf/vczjk/bt4;

    iput-wide p2, p0, Llyiahf/vczjk/vs4;->$animationTarget:J

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    check-cast p1, Llyiahf/vczjk/gi;

    iget-object v0, p0, Llyiahf/vczjk/vs4;->this$0:Llyiahf/vczjk/bt4;

    invoke-virtual {p1}, Llyiahf/vczjk/gi;->OooO0Oo()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/u14;

    iget-wide v1, p1, Llyiahf/vczjk/u14;->OooO00o:J

    iget-wide v3, p0, Llyiahf/vczjk/vs4;->$animationTarget:J

    invoke-static {v1, v2, v3, v4}, Llyiahf/vczjk/u14;->OooO0OO(JJ)J

    move-result-wide v1

    sget p1, Llyiahf/vczjk/bt4;->OooOo00:I

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/bt4;->OooO0oO(J)V

    iget-object p1, p0, Llyiahf/vczjk/vs4;->this$0:Llyiahf/vczjk/bt4;

    iget-object p1, p1, Llyiahf/vczjk/bt4;->OooO0OO:Llyiahf/vczjk/et4;

    invoke-virtual {p1}, Llyiahf/vczjk/et4;->OooO00o()Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
