.class public final synthetic Llyiahf/vczjk/kj0;
.super Llyiahf/vczjk/wf3;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# static fields
.field public static final OooOOO:Llyiahf/vczjk/kj0;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    new-instance v0, Llyiahf/vczjk/kj0;

    const-string v4, "createSegment(JLkotlinx/coroutines/channels/ChannelSegment;)Lkotlinx/coroutines/channels/ChannelSegment;"

    const/4 v5, 0x1

    const/4 v1, 0x2

    const-class v2, Llyiahf/vczjk/lj0;

    const-string v3, "createSegment"

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/wf3;-><init>(ILjava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    sput-object v0, Llyiahf/vczjk/kj0;->OooOOO:Llyiahf/vczjk/kj0;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->longValue()J

    move-result-wide v1

    move-object v3, p2

    check-cast v3, Llyiahf/vczjk/kt0;

    sget-object p1, Llyiahf/vczjk/lj0;->OooO00o:Llyiahf/vczjk/kt0;

    new-instance v0, Llyiahf/vczjk/kt0;

    iget-object v4, v3, Llyiahf/vczjk/kt0;->OooOOo0:Llyiahf/vczjk/jj0;

    invoke-static {v4}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    const/4 v5, 0x0

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/kt0;-><init>(JLlyiahf/vczjk/kt0;Llyiahf/vczjk/jj0;I)V

    return-object v0
.end method
